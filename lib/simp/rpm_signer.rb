require 'find'
require 'parallel'
require 'simp/rpm'
require 'simp/command_utils'

module Simp; end

# Class to sign RPMs.  Uses 'gpg' and 'rpmsign' executables.
class Simp::RpmSigner
  require 'expect'
  require 'pty'

  include Simp::CommandUtils

  @@gpg_keys = Hash.new

  # Kill the GPG agent operating with the specified key dir, if
  # rpm version 4.13.0 or later.
  #
  # Beginning with version 4.13.0, rpm stands up a gpg-agent when
  # a signing operation is requested.
  def self.kill_gpg_agent(gpg_keydir)
    return if Gem::Version.new(Simp::RPM.version) < Gem::Version.new('4.13.0')

    `gpg-agent --homedir #{gpg_keydir} -q >& /dev/null`
    if $? && $?.exitstatus == 0
      # gpg-agent is running for specified keydir, so query it for its pid
      output = %x{echo 'GETINFO pid' | gpg-connect-agent --homedir=#{gpg_keydir}}
      if $? && $?.exitstatus == 0
        pid = output.lines.first[1..-1].strip.to_i
        begin
          Process.kill(0, pid)
          Process.kill(15, pid)
        rescue Errno::ESRCH
          # No longer running, so nothing to do!
        end
      end
    end
  end

  # Loads metadata for a GPG key found in gpg_keydir.
  #
  # The GPG key is to be used to sign RPMs. If the required metadata
  # cannot be found in gpg_keydir, then the user will be prompted for it.
  #
  # @param gpg_keydir The full path of the directory where the key resides
  # @param verbose    Whether to log debug information.
  #
  # @raise If the 'gpg' executable cannot be found, the GPG key directory
  #   does not exist or the GPG key metadata cannot be determined via 'gpg'
  #
  def self.load_key(gpg_keydir, verbose = false)
    which('gpg') || raise("ERROR: Cannot sign RPMs without 'gpg'")
    File.directory?(gpg_keydir) || raise("ERROR: Could not find GPG keydir '#{gpg_keydir}'")

    gpg_key = File.basename(gpg_keydir)

    if @@gpg_keys[gpg_key]
      return @@gpg_keys[gpg_key]
    end

    gpg_name = nil
    gpg_password = nil
    begin
      File.read("#{gpg_keydir}/gengpgkey").each_line do |ln|
        name_line = ln.split(/^\s*Name-Email:/)
        if name_line.length > 1
          gpg_name = name_line.last.strip
        end

        passwd_line = ln.split(/^\s*Passphrase:/)
        if passwd_line.length > 1
          gpg_password = passwd_line.last.strip
        end
      end
    rescue Errno::ENOENT
    end

    if gpg_name.nil?
      puts "Warning: Could not find valid e-mail address for use with GPG."
      puts "Please enter e-mail address to use:"
      gpg_name = $stdin.gets.strip
    end

    if gpg_password.nil?
      if File.exist?(%(#{gpg_keydir}/password))
        gpg_password = File.read(%(#{gpg_keydir}/password)).chomp
      end

      if gpg_password.nil?
        puts "Warning: Could not find a password in '#{gpg_keydir}/password'!"
        puts "Please enter your GPG key password:"
        system 'stty -echo'
        gpg_password = $stdin.gets.strip
        system 'stty echo'
      end
    end

    gpg_key_size = nil
    gpg_key_id = nil
    # gpg_name is an email, so enclose in <> to only search for keys
    # that match that email address
    cmd = "gpg --with-colons --homedir=#{gpg_keydir} --list-keys '<#{gpg_name}>' 2>&1"
    puts "Executing: #{cmd}" if verbose
    %x(#{cmd}).each_line do |line|
      # See https://github.com/CSNW/gnupg/blob/master/doc/DETAILS
      # Index  Content
      #   0    record type
      #   2    key length
      #   4    keyID
      fields = line.split(':')
      if fields[0] && (fields[0] == 'pub')
        gpg_key_size = fields[2]
        gpg_key_id = fields[4]
        break
      end
    end

    if !gpg_key_size || !gpg_key_id
      raise('Error getting GPG Key metadata')
    end

    @@gpg_keys[gpg_key] = {
      :dir => gpg_keydir,
      :name => gpg_name,
      :key_id => gpg_key_id,
      :key_size => gpg_key_size,
      :password => gpg_password
    }
  end

  # Signs the given RPM with the GPG key found in gpg_keydir
  #
  # @param rpm        Fully qualified path to an RPM to be signed.
  # @param gpg_keydir The full path of the directory where the key resides.
  # @param verbose    Whether to log debug information.
  #
  # @raise RuntimeError if 'rpmsign' executable cannot be found, the 'gpg
  #   'executable cannot be found, the GPG key directory does not exist or
  #   the GPG key metadata cannot be determined via 'gpg'
  def self.sign_rpm(rpm, gpg_keydir, verbose = false)
    # This may be a little confusing...Although we're using 'rpm --resign'
    # in lieu of 'rpmsign --addsign', they are equivalent and the presence
    # of 'rpmsign' is a legitimate check that the 'rpm --resign' capability
    # is available (i.e., rpm-sign package has been installed).
    which('rpmsign') || raise("ERROR: Cannot sign RPMs without 'rpmsign'.")

    gpgkey = load_key(gpg_keydir, verbose)

    gpg_digest_algo = nil
    gpg_sign_cmd_extra_args = nil
    if Gem::Version.new(Simp::RPM.version) >= Gem::Version.new('4.13.0')
      gpg_digest_algo = "--define '%_gpg_digest_algo sha256'"
      gpg_sign_cmd_extra_args = "--define '%_gpg_sign_cmd_extra_args --pinentry-mode loopback --verbose'"
#      gpg_sign_cmd = "--define '%__gpg_sign_cmd %{__gpg} gpg --pinentry-mode loopback --verbose --no-armor --no-secmem-warning -u \"%{_gpg_name}\" -sbo %{__signature_filename} --digest-algo sha256 %{__plaintext_filename}'"
    end

    signcommand = [
      'rpm',
      "--define '%_signature gpg'",
      "--define '%__gpg %{_bindir}/gpg'",
      "--define '%_gpg_name #{gpgkey[:name]}'",
      "--define '%_gpg_path #{gpgkey[:dir]}' ",
      gpg_digest_algo,
      gpg_sign_cmd_extra_args,
      "--resign #{rpm}"
     ].compact.join(' ')

    begin
      if verbose
        puts "Signing #{rpm} with #{gpgkey[:name]} from #{gpgkey[:dir]}:\n  #{signcommand}"
      end
      PTY.spawn(signcommand) do |read, write, pid|
        begin
          while !read.eof? do
            # rpm version >= 4.13.0 will stand up a gpg-agent and so the prompt
            # for the passphrase will only actually happen if this is the first
            # RPM to be signed with the key after the gpg-agent is started and the
            # key's passphrase has not been cleared from the agent's cache.
            read.expect(/pass\s?phrase:.*/) do |text|
              write.puts(gpgkey[:password])
              write.flush
            end
          end
        rescue Errno::EIO
          # Will get here once input is no longer needed, which can be
          # immediately, if a gpg-agent is already running and the
          # passphrase for the key is loaded in its cache.
        end

        Process.wait(pid)
      end

      raise "Failure running #{signcommand}" unless $?.success?
    rescue Exception => e
      $stderr.puts "Error occurred while attempting to sign #{rpm}, skipping."
      $stderr.puts e
    end
  end

  # Signs any RPMs found within the entire rpm_dir directory tree with
  # the GPG key found in gpg_keydir
  #
  # @param rpm_dir    A directory or directory glob pattern specifying 1 or
  #                   more directories containing RPM files to sign.
  # @param gpg_keydir The full path of the directory where the key resides
  # @param force      Force RPMs that are already signed to be resigned.
  # @param progress_bar_title Title for the progress bar logged to the
  #                   console during the signing process.
  # @param max_concurrent Maximum number of concurrent RPM signing
  #                   operations
  # @param verbose    Whether to log debug information.
  #
  # @raise RuntimeError if 'rpmsign' executable cannot be found, the 'gpg'
  #   executable cannot be found, the GPG key directory does not exist or
  #   the GPG key metadata cannot be determined via 'gpg'
  #
  #   **All other RPM signing errors are logged and ignored.**
  #
  def self.sign_rpms(rpm_dir, gpg_keydir, force=false,
      progress_bar_title = 'sign_rpms', max_concurrent = 1, verbose = false)

    rpm_dirs = Dir.glob(rpm_dir)
    to_sign = []

    rpm_dirs.each do |rpm_dir|
      Find.find(rpm_dir) do |rpm|
        next unless File.readable?(rpm)
        to_sign << rpm if rpm =~ /\.rpm$/
      end
    end

    begin
      Parallel.map(
        to_sign,
        :in_processes => max_concurrent,
        :progress => progress_bar_title
      ) do |rpm|

        if force || !Simp::RPM.new(rpm, verbose).signature
          sign_rpm(rpm, gpg_keydir, verbose)
        else
          puts "Skipping signed package #{rpm}" if verbose
        end
      end
    ensure
      kill_gpg_agent(gpg_keydir)
    end
  end
end
