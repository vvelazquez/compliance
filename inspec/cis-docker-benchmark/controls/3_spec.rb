# encoding: utf-8
# copyright: 2017 Docker, Inc.
# license: Apache-2.0

title '3 Docker daemon configuration files'

control 'cis-3.1' do
  impact 0.7
  title '3.1 Verify that docker.service file ownership is set to root:root (Scored)'
  desc '
    Verify that the ''docker.service'' file ownership and group-ownership are correctly set to
    ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.1', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  systemd_service_file = command('systemctl show -p FragmentPath docker.service | sed "s/.*=//" | tr -d "\n"').stdout

  only_if do
    file(systemd_service_file).exist?
  end

  describe file(systemd_service_file) do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.2' do
  impact 0.7
  title '3.2 Verify that docker.service file permissions are set to 644 or more restrictive (Scored)'
  desc '
    Verify that the ''docker.service'' file permissions are correctly set to ''644'' or more
    restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.2', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  systemd_service_file = command('systemctl show -p FragmentPath docker.service | sed "s/.*=//" | tr -d "\n"').stdout

  only_if do
    file(systemd_service_file).exist?
  end

  describe.one do
    describe file(systemd_service_file) do
      it { should exist }
      its('mode') { should eq 0644 }
    end

    describe file(systemd_service_file) do
      it { should exist }
      its('mode') { should eq 0600 }
    end
  end
end

control 'cis-3.3' do
  impact 0.7
  title '3.3 Verify that docker.socket file ownership is set to root:root (Scored)'
  desc '
    Verify that the ''docker.socket'' file ownership and group-ownership are correctly set to
    ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.3', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  systemd_service_file = command('systemctl show -p FragmentPath docker.socket | sed "s/.*=//" | tr -d "\n"').stdout

  only_if do
    file(systemd_service_file).exist?
  end

  describe file(systemd_service_file) do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.4' do
  impact 0.7
  title '3.4 Verify that docker.socket file permissions are set to 644 or more restrictive (Scored)'
  desc '
    Verify that the ''docker.socket'' file permissions are correctly set to ''644'' or more
    restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.4', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  systemd_service_file = command('systemctl show -p FragmentPath docker.socket | sed "s/.*=//" | tr -d "\n"').stdout

  only_if do
    file(systemd_service_file).exist?
  end

  describe.one do
    describe file(systemd_service_file) do
      it { should exist }
      its('mode') { should eq 0644 }
    end

    describe file(systemd_service_file) do
      it { should exist }
      its('mode') { should eq 0600 }
    end
  end
end

control 'cis-3.5' do
  impact 0.7
  title '3.5 Verify that /etc/docker directory ownership is set to root:root (Scored)'
  desc '
    Verify that /etc/docker direcotry ownership and group-ownership is correctly set to
    ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.5', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    directory('/etc/docker').exist?
  end

  describe directory('/etc/docker') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.6' do
  impact 0.7
  title '3.6 Verify that /etc/docker directory permissions are set to 755 or more restrictive (Scored)'
  desc '
    Verify that the /etc/docker directory permissions are correctly set to ''755'' or more
    restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.6', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    directory('/etc/docker').exist?
  end

  describe.one do
    describe directory('/etc/docker') do
      it { should exist }
      its('mode') { should eq 0755 }
    end

    describe directory('/etc/docker') do
      it { should exist }
      its('mode') { should eq 0700 }
    end
  end
end

control 'cis-3.7' do
  impact 0.7
  title '3.7 Verify that registry certificate file ownership is set to root:root (Scored)'
  desc '
    Verify that all the registry certificate files (usually found
    under /etc/docker/certs.d/<registry-name> directory) are owned and group-owned by
    ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.7', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    directory('/etc/docker/certs.d').exist?
  end

  owners = command("find /etc/docker/certs.d -type f -name '*.crt'").stdout.split("\n")
  owners.each do |owner|
    describe file(owner) do
      its('owner') { should eq 'root' }
    end
  end
end

control 'cis-3.8' do
  impact 0.7
  title 'Verify that registry certificate file permissions are set to 444 or more restrictive (Scored)'
  desc '
    Verify that all the registry certificate files (usually found
    under /etc/docker/certs.d/<registry-name> directory) have permissions of ''444'' or
    more restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.8', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    directory('/etc/docker/certs.d').exist?
  end

  perms = command("find /etc/docker/certs.d -type f -name '*.crt'").stdout.split("\n")
  perms.each do |perm|
    describe.one do
      describe file(perm) do
        its('mode') { should eq 0444 }
      end

      describe file(perm) do
        its('mode') { should eq 0400 }
      end
    end
  end
end

control 'cis-3.9' do
  impact 0.7
  title '3.9 Verify that TLS CA certificate file ownership is set to root:root (Scored)'
  desc '
    Verify that the TLS CA certificate file (the file that is passed alongwith ''--
    tlscacert'' parameter) is owned and group-owned by ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.9', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    processes('dockerd').where { command =~ /--tlscacert/ }
  end

  tlscacertarg = processes('dockerd').commands[0].split(' ').find{ |arg| arg[/--tlscacert=/] }
  tlscacert = tlscacertarg ? /--tlscacert=(?<tlscacert>.*)/.match(tlscacertarg)[:tlscacert] : nil

  only_if do
    file(tlscacert).exist?
  end

  describe file(tlscacert) do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.10' do
  impact 0.7
  title '3.10 Verify that TLS CA certificate file permissions are set to 444 or more restrictive (Scored)'
  desc '
    Verify that the TLS CA certificate file (the file that is passed alongwith ''--
    tlscacert'' parameter) has permissions of ''444'' or more restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.10', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    processes('dockerd').where { command =~ /--tlscacert/ }
  end

  tlscacertarg = processes('dockerd').commands[0].split(' ').find{ |arg| arg[/--tlscacert=/] }
  tlscacert = tlscacertarg ? /--tlscacert=(?<tlscacert>.*)/.match(tlscacertarg)[:tlscacert] : nil

  only_if do
    file(tlscacert).exist?
  end

  describe.one do
    describe file(tlscacert) do
      its('mode') { should eq 0444 }
    end

    describe file(tlscacert) do
      its('mode') { should eq 0400 }
    end
  end
end

control 'cis-3.11' do
  impact 0.7
  title '3.11 Verify that Docker server certificate file ownership is set to root:root (Scored)'
  desc '
    Verify that the Docker server certificate file (the file that is passed alongwith ''--
    tlscert'' parameter) is owned and group-owned by ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.11', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    processes('dockerd').where { command =~ /--tlscert/ }
  end

  tlscertarg = processes('dockerd').commands[0].split(' ').find{ |arg| arg[/--tlscert=/] }
  tlscert = tlscertarg ? /--tlscert=(?<tlscert>.*)/.match(tlscertarg)[:tlscert] : nil

  only_if do
    file(tlscert).exist?
  end

  describe file(tlscert) do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.12' do
  impact 0.7
  title '3.12 Verify that Docker server certificate file permissions are set to 444 or more restrictive (Scored)'
  desc '
    Verify that Docker server certificate file (the file that is passed alongwith ''--
    tlscert'' parameter) has permissions of ''444'' or more restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.12', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    processes('dockerd').where { command =~ /--tlscert/ }
  end

  tlscertarg = processes('dockerd').commands[0].split(' ').find{ |arg| arg[/--tlscert=/] }
  tlscert = tlscertarg ? /--tlscert=(?<tlscert>.*)/.match(tlscertarg)[:tlscert] : nil

  only_if do
    file(tlscert).exist?
  end

  describe.one do
    describe file(tlscert) do
      its('mode') { should eq 0444 }
    end

    describe file(tlscert) do
      its('mode') { should eq 0400 }
    end
  end
end

control 'cis-3.13' do
  impact 0.7
  title '3.13 Verify that Docker server certificate key file ownership is set to root:root (Scored)'
  desc '
    Verify that the Docker server certificate key file (the file that is passed alongwith ''--
    tlskey'' parameter) is owned and group-owned by ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.13', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    !processes('dockerd').where { command =~ /--tlskey/ }.entries.empty?
  end

  tlskeyarg = processes('dockerd').commands[0].split(' ').find{ |arg| arg[/--tlskey=/] }
  tlskey = tlskeyarg ? /--tlskey=(?<tlskey>.*)/.match(tlskeyarg)[:tlskey] : nil

  only_if do
    file(tlskey).exist?
  end

  describe file(tlskey) do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.14' do
  impact 0.7
  title '3.14 Verify that Docker server certificate key file permissions are set to 400 (Scored)'
  desc '
    Verify that the Docker server certificate key file (the file that is passed alongwith ''--
    tlskey'' parameter) has permissions of ''400''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.14', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    !processes('dockerd').where { command =~ /--tlskey/ }.entries.empty?
  end

  tlskeyarg = processes('dockerd').commands[0].split(' ').find{ |arg| arg[/--tlskey=/] }
  tlskey = tlskeyarg ? /--tlskey=(?<tlskey>.*)/.match(tlskeyarg)[:tlskey] : nil

  only_if do
    file(tlskey).exist?
  end

  describe.one do
    describe file(tlskey) do
      its('mode') { should eq 0444 }
    end

    describe file(tlskey) do
      its('mode') { should eq 0400 }
    end
  end
end

control 'cis-3.15' do
  impact 0.7
  title '3.15 Verify that Docker socket file ownership is set to root:docker (Scored)'
  desc '
    Verify that the Docker socket file is owned by ''root'' and group-owned by ''docker''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.15', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    file('/var/run/docker.sock').exist?
  end

  describe file('/var/run/docker.sock') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'docker' }
  end
end

control 'cis-3.16' do
  impact 0.7
  title '3.16 Verify that Docker socket file permissions are set to 660 or more restrictive (Scored)'
  desc '
    Verify that the Docker socket file has permissions of ''660'' or more restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.16', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    file('/var/run/docker.sock').exist?
  end

  describe.one do
    describe file('/var/run/docker.sock') do
      it { should exist }
      its('mode') { should eq 0660 }
    end

    describe file('/var/run/docker.sock') do
      it { should exist }
      its('mode') { should eq 0600 }
    end
  end
end

control 'cis-3.17' do
  impact 0.7
  title '3.17 Verify that daemon.json file ownership is set to root:root (Scored)'
  desc '
    Verify that the ''daemon.json'' file ownership and group-ownership is correct set to ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.17', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    file('/etc/docker/daemon.json').exist?
  end

  describe file('/etc/docker/daemon.json') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.18' do
  impact 0.7
  title '3.18 Verify that daemon.json file permissions are set to 644 or more restrictive (Scored)'
  desc '
    Verify that the ''daemon.json'' file permissions are correctly set to ''644'' or more restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.18', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    file('/etc/docker/daemon.json').exist?
  end

  describe.one do
    describe file('/etc/docker/daemon.json') do
      it { should exist }
      its('mode') { should eq 0644 }
    end

    describe file('/etc/docker/daemon.json') do
      it { should exist }
      its('mode') { should eq 0600 }
    end
  end
end

control 'cis-3.19' do
  impact 0.7
  title '3.19 Verify that /etc/default/docker file ownership is set to root:root (Scored)'
  desc '
    Verify that the ''/etc/default/docker'' file ownership and group-ownership is correctly set
    to ''root''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.19', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    file('/etc/default/docker').exist?
  end

  describe file('/etc/default/docker') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end

control 'cis-3.20' do
  impact 0.7
  title '3.20 Verify that /etc/default/docker file permissions are set to 644 or more restrictive (Scored)'
  desc '
    Verify that the ''/etc/default/docker'' file permissions are correctly set to ''644'' or more
    restrictive.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 3.20', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    file('/etc/default/docker').exist?
  end

  describe.one do
    describe file('/etc/default/docker') do
      it { should exist }
      its('mode') { should eq 0644 }
    end

    describe file('/etc/default/docker') do
      it { should exist }
      its('mode') { should eq 0600 }
    end
  end
end
