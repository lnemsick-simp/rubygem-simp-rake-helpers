require 'securerandom'
require 'rake'
require 'simp/command_utils'

module Simp
  # Ensure that a valid GPG signing key exists in a local directory
  #
  #   This is typically used to sign packages during development.
  #
  #   * The signing key will be generated if it is missing or expired.
  #   * Generated keys are short-lived (default: 14 days).
  #   * The signing key and its related assets are completely isolated from
  #     the user's own GPG keys, keyrings, and agent.
  #     - All files are kept under a local directory tree.
  #     - New keys are generated using a temporary GPG agent with its own
  #       settings and socket.
  #
  #   The local signing key's directory includes the following:
  #   gpg < 2.1.0 (EL7):
  #
  #   ```
  #   #{key_name}/                        # key directory
  #     +-- RPM-GPG-KEY-SIMP-#{key_name}  # key file
  #     +-- gengpgkey                     # --gen-key params file **
  #     +-- gpg-agent-info.env            # Lists location of gpg-agent socket + pid
  #     +-- run_gpg_agnet                 # Script used to start gpg-agent
  #     +-- pubring.gpg
  #     +-- secring.gpg
  #     +-- trustdb.gpg
  #   ```
  #
  #   gpg >= 2.1.0 (EL8):
  #   ```
  #   #{key_name}/                        # key directory
  #     +-- RPM-GPG-KEY-SIMP-#{key_name}  # key file
  #     +-- gengpgkey                     # --gen-key params file **
  #     +-- openpgp-revocs.d/<fingerprint id>.rev
  #     +-- private-keys-v1.d/<user id>.key
  #     +-- pubring.kbx
  #     +-- trustdb.gpg
  #   ```
  #
  #   `**` = `SIMP::RpmSigner.sign_rpms` will use the values in the `gengpgkey` file
  #     for the GPG signing key's email and passphrase
  #
  #   If a new key is required, a project-only `gpg-agent` daemon is momentarily
  #   created to generate it, and destroyed after this is done.  The daemon does
  #   not interact with any other `gpg-agent` daemons on the system. It is
  #   launched on random socket(s) whose socket file(s) can be found as follows:
  #   * when building in a Docker container for EL8: #{key_name/} directory
  #   * when building outside of a Docker container for EL8: a temporary
  #     directory in /run/user/<uid>/gnupg
  #   * when building for El7: a temporary directory in /tmp (EL7)
  #
  class LocalGpgSigningKey
    include FileUtils
    include Simp::CommandUtils

    # `SIMP::RpmSigner.sign_rpms` will look for a 'gengpgkey' file to
    #   non-interactively sign packages.
    #
    #   @see SIMP::RpmSigner.sign_rpms
    GPG_GENKEY_PARAMS_FILENAME = 'gengpgkey'.freeze

    # @param dir  [String] path to gpg-agent / key directory
    # @param opts [Hash] optional configurations
    #
    # @option opts [String]  :label         Defaults to the basename of `dir` (dev)
    # @option opts [String]  :email         (gatekeeper@simp.development.key)
    # @option opts [String]  :file          Default based on label (RPM-GPG-KEY-SIMP-Dev)
    # @option opts [Boolean] :verbose       (false)
    #
    def initialize(dir = 'dev', opts = {})
      @dir       = File.expand_path(dir)
      @label     = opts[:label]   || File.basename(dir.downcase)
      @key_email = opts[:email]   || 'gatekeeper@simp.development.key'
      @key_file  = opts[:file]    || "RPM-GPG-KEY-SIMP-#{@label.capitalize}"
      @verbose   = opts[:verbose] || false

      # for EL7 only
      @gpg_agent_env_file = 'gpg-agent-info.env'
      @gpg_agent_script   = 'run_gpg_agent'
    end

    # Return the version of GPG instealled on the system
    #
    # @return [Gem::Version]
    def gpg_version
      return @gpg_version if @gpg_version

      which('gpg', true)
      @gpg_version = %x{gpg --version}.lines.first.split(/\s+/).last

      unless @gpg_version.nil? || @gpg_version.empty?
        @gpg_version = Gem::Version.new(@gpg_version)
      end

      @gpg_version
    end

    # Returns a gpg-agent's env string, if it can be detected from the
    #   gpg-agent-info file
    #
    # @return [String] if the env string was detected
    # @return [nil]    if the env string was not detected
    #
    def gpg_agent_info
      if File.exist?(@gpg_agent_env_file)
        puts "Reading gpg_agent_info from `#{@gpg_agent_env_file}`..." if @verbose
        info = parse_gpg_agent_info_env(File.read(@gpg_agent_env_file))
      else
        puts "Couldn't find a valid source to read gpg_agent_info..." if @verbose
        info = nil
      end
      info
    end

    # Return the number of days left before the GPG signing key expires
    def dev_key_days_left
      ensure_gpg_directory
      days_left   = 0

      which('gpg', true)
      # FIXME This output parsing is fragile. Should use --with-colons option!
      current_key = %x(GPG_AGENT_INFO='' gpg --homedir=#{@dir} --list-keys #{@key_email} 2>/dev/null)
      unless current_key.empty?
        lasts_until = current_key.lines.first.strip.split("\s").last.delete(']')
        days_left = (Date.parse(lasts_until) - Date.today).to_i
      end
      days_left
    end

    # Remove all files under the key directory
    def clean_gpg_agent_directory
      puts "  Removing all files under '#{@dir}'" if @verbose
      Dir.glob(File.join(@dir, '*')).each do |todel|
        rm_rf(todel, :verbose => @verbose)
      end
    end

    # Make sure the local key's directory exists and has correct permissions
    def ensure_gpg_directory
      mkdir_p(@dir, :verbose => @verbose)
      chmod(0o700, @dir, :verbose => @verbose)
    end

    # Ensure that the gpg-agent is running with a dev key
    def ensure_key
      ensure_gpg_directory

      if (days_left = dev_key_days_left) > 0
        puts "GPG key (#{@key_email}) will expire in #{days_left} days."
        return
      end

      Dir.chdir @dir do |_dir|
        puts 'Creating a new dev GPG agent...'

        clean_gpg_agent_directory
        write_genkey_parameter_file

        begin
          if gpg_version < Gem::Version.new('2.1')
            write_gpg_agent_startup_script

            # Start the GPG agent.
            gpg_agent_output = %x(./#{@gpg_agent_script}).strip

            # By the time we get here, we can be assured we will be starting a
            # new agent, because the directory is cleaned out.
            #
            # Follow-on gpg actions will read the agent's information from
            # the env-file the agent writes at startup.

            # We're using the --sh option which will spew out the agent config
            # when the agent starts. If it is empty, this is a problem.
            warn(empty_gpg_agent_message) if gpg_agent_output.empty?

            agent_info = gpg_agent_info

            # The local socket is useful to get back info on the command line.
            local_socket = File.join(Dir.pwd, 'S.gpg-agent')
            unless File.exist?(File.join(Dir.pwd, File.basename(agent_info[:socket])))
              ln_s(agent_info[:socket], local_socket, :verbose => @verbose)
            end

            generate_key(agent_info[:info])
          else
            which('gpg', true)
            which('gpg-agent', true)
            which('gpg-connect-agent', true)

            # Start the GPG agent, if it is not already running
            %x{gpg-agent -q --homedir=#{Dir.pwd} >&/dev/null || gpg-agent --homedir=#{Dir.pwd} --daemon >&/dev/null}

            agent_info = {}

            # Provide a local socket (needed by the `gpg` command when
            agent_info[:socket] = %x{echo 'GETINFO socket_name' | gpg-connect-agent --homedir=#{Dir.pwd}}.lines.first[1..-1].strip

            # Get the pid
            agent_info[:pid] = %x{echo 'GETINFO pid' | gpg-connect-agent --homedir=#{Dir.pwd}}.lines.first[1..-1].strip.to_i

            generate_key(%{#{agent_info[:socket]}:#{agent_info[:pid]}:1})
          end
        ensure
          kill_agent(agent_info[:pid])
        end

        agent_info
      end
    end

    # Provides an informative warning message to display in the unlikely event
    #   that a new `gpg-agent` daemon returns empty output when it is started.
    #
    # @return [String] Warning message
    def empty_gpg_agent_message
      <<-WARNING.gsub(/^\s{8}/,'')
        WARNING: Tried to start an project-only gpg-agent daemon on a random socket by
                 running the script:

                   #{@gpg_agent_script}

                 However, the script returned no output, which usually means that a GPG
                 Agent was already running on that socket.  This is extraordinarily
                 unlikely, and is not expected to happen.

                 If the '#{@label}' GPG signing key fails to generate after this
                 message appears, please report this issue to the SIMP project,
                 including the OS you were were running from and its versions of the
                 `gpg-agent` and `gpg`/`gpg2` commands.
      WARNING
    end

    # Kills the GPG agent by pid, if it is running
    #
    # @param pid [String] The GPG Agent PID to kill
    def kill_agent(pid)
      rm('S.gpg-agent') if File.symlink?('S.gpg-agent')
      if pid
        Process.kill(0, pid)
        Process.kill(15, pid)
      end
    rescue Errno::ESRCH
      # Not Running, Nothing to do!
    end

    # Generate a RPM GPG signing key for local development
    #
    # @param gpg_agent_info_str [String] value to set the GPG_AGENT_INFO
    #   environment variable to use in order to use the correct `gpg-agent`.
    def generate_key(gpg_agent_info_str)
      which('gpg', true)

      puts "Generating new GPG key#{@verbose ? " under '#{@dir}'" : ''}..."
      gpg_cmd = %(GPG_AGENT_INFO=#{gpg_agent_info_str} gpg --homedir="#{@dir}")

      pipe    = @verbose ? '| tee' : '>'
      sh %(#{gpg_cmd} --batch --gen-key #{GPG_GENKEY_PARAMS_FILENAME})
      sh %(#{gpg_cmd} --armor --export #{@key_email} #{pipe} "#{@key_file}")

      if File.stat(@key_file).size == 0
        fail "Error: Something went wrong generating #{@key_file}"
      end
    end

    # Return a data structure from a gpg-agent env-file formatted string.
    #
    # @param str [String] path to gpg-agent / key directory
    def parse_gpg_agent_info_env(str)
      info    = %r{^(GPG_AGENT_INFO=)?(?<info>[^;]+)}.match(str)[:info]
      matches = %r{^(?<socket>[^:]+):(?<pid>[^:]+)}.match(info)
      { info: info.strip, socket: matches[:socket], pid: matches[:pid].to_i }
    end

    # Write the `gpg --genkey --batch` control parameter file
    #
    # @see "Unattended key generation" in /usr/share/doc/gnupg2-*/DETAILS for
    #   documentation on the command parameters format
    def write_genkey_parameter_file
      now               = Time.now.to_i.to_s
      expire_date       = Date.today + 14
      passphrase        = SecureRandom.base64(100)
      genkey_parameters = [
        '%echo Generating Development GPG Key',
        '%echo',
        "%echo This key will expire on #{expire_date}",
        '%echo',
        'Key-Type: RSA',
        'Key-Length: 4096',
        'Key-Usage: sign',
        'Name-Real: SIMP Development',
        "Name-Comment: Development key #{now}",
        "Name-Email: #{@key_email}",
        'Expire-Date: 2w',
        "Passphrase: #{passphrase}",
      ]

      if gpg_version < Gem::Version.new('2.1')
        genkey_parameters << '%pubring pubring.gpg'
        genkey_parameters << '%secring secring.gpg'
      end

      genkey_parameters << '# The following creates the key, so we can print "Done!" afterwards'
      genkey_parameters << '%commit'
      genkey_parameters << '%echo New GPG Development Key Created'

      File.open(GPG_GENKEY_PARAMS_FILENAME, 'w') { |fh| fh.puts(genkey_parameters.join("\n")) }
    end

    # Write a local gpg-agent daemon script file
    def write_gpg_agent_startup_script
      which('gpg-agent', true)
      pinentry_cmd = which('pinentry-curses', true)

      gpg_agent_script = <<-AGENT_SCRIPT.gsub(%r{^ {20}}, '')
        #!/bin/sh

        gpg-agent --homedir=#{Dir.pwd} --daemon \
          --no-use-standard-socket --sh --batch \
          --write-env-file "#{@gpg_agent_env_file}" \
          --pinentry-program #{pinentry_cmd} < /dev/null &
      AGENT_SCRIPT

      File.open(@gpg_agent_script, 'w') { |fh| fh.puts(gpg_agent_script) }
      chmod(0o755, @gpg_agent_script)
    end
  end
end
