# encoding: utf-8
# copyright: 2017 Docker, Inc
# license: Apache 2.0

title '1 Host Configuration'

control 'cis-1.1' do
  impact 0.7
  title '1.1 Create a separate partition for containers (Scored)'
  desc '
    All Docker containers and their data and metadata is stored under /var/lib/docker
    directory. By default, /var/lib/docker would be mounted under / or /var partitions based
    on availability.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.1', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe file('/etc/fstab') do
    its('content') { should match /\/var\/lib\/docker/ }
  end
end

control 'cis-1.2' do
  impact 0.7
  title '1.2 Harden the container host (Scored)'
  desc '
    Containers run on a Linux host. A container host can run one or more containers. It is of
    utmost importance to harden the host to mitigate host security misconfiguration.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.2', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'
  
  puts "\n[NOTE]1.2  - Harden the container host"
end

control 'cis-1.3' do
  impact 0.7
  title '1.3 Keep Docker up to date (Not Scored)'
  desc '
    There are frequent releases for Docker software that address security vulnerabilities,
    product bugs and bring in new functionality. Keep a tab on these product updates and
    upgrade as frequently as when new security vulnerabilities are fixed or deemed correct for
    your organization.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.3', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe.one do
    describe package('docker-ce') do
      it { should be_installed }
      its('version') { should be >= '17.03' }
    end

    describe package('docker-ee') do
      it { should be_installed }
      its('version') { should be >= '17.03' }
    end
  end
end

control 'cis-1.4' do
  impact 0.7
  title '1.4 Only allow trusted users to control Docker daemon (Scored)'
  desc '
    The Docker daemon currently requires ''root'' privileges. A user added to the ''docker''
    group gives him full ''root'' access rights.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.4', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe command('getent group docker') do
    its('stdout') { should match /docker:*/ }
  end
end

control 'cis-1.5' do
  impact 0.7
  title '1.5 Audit docker daemon (Scored)'
  desc '
    Audit all Docker daemon activities.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.5', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /usr/bin/docker}) }
  end
end

control 'cis-1.6' do
  impact 0.7
  title '1.6 Audit Docker files and directories - /var/lib/docker (Scored)'
  desc '
    Audit /var/lib/docker.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.6', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /var/lib/docker}) }
  end
end

control 'cis-1.7' do
  impact 0.7
  title '1.7 Audit Docker files and directories (Scored)'
  desc '
    Audit /etc/docker.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.7', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /etc/docker}) }
  end
end

control 'cis-1.8' do
  impact 0.7
  title '1.8 Audit Docker files and directories - docker.service (Scored)'
  desc '
    Audit /etc/docker.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.8', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  systemd_service_file = command('systemctl show -p FragmentPath docker.service | sed "s/.*=//"').stdout
  audit_lines = systemd_service_file != "\n" ? [ systemd_service_file, '/etc/systemd/system/docker.service', '/usr/lib/systemd/system/docker.service' ] : [ '/etc/systemd/system/docker.service', '/usr/lib/systemd/system/docker.service' ]
  audit_lines.each do |line|
    describe auditd_rules do
      its('lines') { should contain_match(%r{-w #{line}}) }
    end
  end
end

control 'cis-1.9' do
  impact 0.7
  title '1.9 Audit Docker files and directories - docker.socket (Scored)'
  desc '
    Audit docker.socket, if applicable.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.9', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  systemd_service_file = command('systemctl show -p FragmentPath docker.socket | sed "s/.*=//"').stdout
  audit_lines = systemd_service_file != "\n" ? [ systemd_service_file, '/etc/systemd/system/docker.socket', '/usr/lib/systemd/system/docker.socket' ] : [ '/etc/systemd/system/docker.socket', '/usr/lib/systemd/system/docker.socket' ]
  audit_lines.each do |line|
    describe auditd_rules do
      its('lines') { should contain_match(%r{-w #{line}}) }
    end
  end
end

control 'cis-1.10' do
  impact 0.7
  title '1.10 Audit Docker files and directories - /etc/default/docker (Scored)'
  desc '
    Audit /etc/default/docker, if applicable.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.10', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /etc/default/docker}) }
  end
end

control 'cis-1.11' do
  impact 0.7
  title '1.11 Audit Docker files and directories - /etc/docker/daemon.json (Scored)'
  desc '
    Audit /etc/docker/daemon.json, if applicable.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.11', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /etc/docker/daemon.json}) }
  end
end

control 'cis-1.12' do
  impact 0.7
  title '1.12 Audit Docker files and directories - /usr/bin/docker-containerd (Scored)'
  desc '
    Audit /usr/bin/docker-containerd, if applicable
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.12', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /usr/bin/docker-containerd}) }
  end
end

control 'cis-1.13' do
  impact 0.7
  title '1.13 Audit Docker files and directories - /usr/bin/docker-runc (Scored)'
  desc '
    Audit /usr/bin/docker-runc, if applicable.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 1.13', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe auditd_rules do
    its('lines') { should contain_match(%r{-w /usr/bin/docker-runc}) }
  end
end
