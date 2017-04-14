# encoding: utf-8
# copyright: 2017 Docker, Inc.
# license: Apache-2.0

title '2 Docker daemon configuration'

control 'cis-2.1' do
  impact 0.7
  title '2.1 Restrict network traffic between containers (Scored)'
  desc '
    By default, all network traffic is allowed between containers on the same host. If not
    desired, restrict all the inter container communication. Link specific containers together
    that require inter communication
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.1', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--icc=false/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.2' do
  impact 0.7
  title '2.2 Set the logging level (Scored)'
  desc '
    Set Docker daemon log level to ''info''.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.2', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe.one do
    describe processes('dockerd').where { command =~ /--log-level=info/ } do
      its('entries') { should_not be_empty }
    end

    describe processes('dockerd').where { command =~ /--log-level/ } do
      its('entries') { should be_empty }
    end
  end
end

control 'cis-2.3' do
  impact 0.7
  title '2.3 Allow Docker to make changes to iptables (Scored)'
  desc '
    Iptables are used to set up, maintain, and inspect the tables of IP packet filter rules in the
    Linux kernel. Allow the Docker daemon to make changes to the iptables.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.3', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe.one do
    describe processes('dockerd').where { command =~ /--iptables=true/ } do
      its('entries') { should_not be_empty }
    end

    describe processes('dockerd').where { command =~ /--iptables/ } do
      its('entries') { should be_empty }
    end
  end
end

control 'cis-2.4' do
  impact 0.7
  title '2.4 Do not use insecure registries (Scored)'
  desc '
    Docker considers a private registry either secure or insecure. By default, registries are
    considered secure.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.4', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--insecure-registry/ } do
    its('entries') { should be_empty }
  end
end

control 'cis-2.5' do
  impact 0.7
  title '2.5 Do not use the aufs storage driver (Scored)'
  desc '
    Do not use ''aufs'' as storage driver for your Docker instance.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.5', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe command('docker info 2>/dev/null | grep -e "^Storage Driver:\s*aufs\s*$"') do
    its('stdout') { should be_empty }
  end
end

control 'cis-2.6' do
  impact 0.7
  title '2.6 Configure TLS authentication for Docker daemon (Scored)'
  desc '
    It is possible to make the Docker daemon to listen on a specific IP and port and any other
    Unix socket other than default Unix socket. Configure TLS authentication to restrict access
    to Docker daemon via IP and port.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.6', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /-H (unix|fd):\/\// } do
    its('entries') { should be_empty }
  end

  describe processes('dockerd').where { command =~ /--tlsverify/ } do
    its('entries') { should_not be_empty }
  end

  describe processes('dockerd').where { command =~ /--tlscacert/ } do
    its('entries') { should_not be_empty }
  end

  describe processes('dockerd').where { command =~ /--tlscert/ } do
    its('entries') { should_not be_empty }
  end

  describe processes('dockerd').where { command =~ /--tlskey/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.7' do
  impact 0.7
  title '2.7 Set default ulimit as appropriate (Not Scored)'
  desc '
    Set the default ulimit options as appropriate in your environment.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.7', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--default-ulimit/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.8' do
  impact 0.7
  title '2.8 Enable user namespace support (Scored)'
  desc '
    Enable user namespace support in Docker daemon to utilize container user to host user remapping.
    This recommendation is beneficial where containers you are using do not have an
    explicit container user defined in the container image. If container images that you are
    using have a pre-defined non-root user, this recommendation may be skipped since this
    feature is still in its infancy and might give you unpredictable issues and complexities.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.8', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--userns-remap=default/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.9' do
  impact 0.7
  title '2.9 Confirm default cgroup usage (Scored)'
  desc '
    The --cgroup-parent option allows you to set the default cgroup parent to use for all the
    containers. If there is no specific use case, this setting should be left at its default.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.9', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe.one do
    describe processes('dockerd').where { command =~ /--cgroup-parent/ } do
      its('entries') { should_not be_empty }
    end

    describe processes('dockerd').where { command =~ /--cgroup-parent/ } do
      its('entries') { should be_empty }
    end
  end
end

control 'cis-2.10' do
  impact 0.7
  title '2.10 Do not change base device size until needed (Scored)'
  desc '
    In certain circumstances, you might need containers bigger than 10G in size. In these cases,
    carefully choose the base device size.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.10', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--storage-opt dm.basesize/ } do
    its('entries') { should be_empty }
  end
end

control 'cis-2.11' do
  impact 0.7
  title '2.11 Use authorization plugin (Scored)'
  desc '
    Use authorization plugin to manage access to Docker daemon.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.11', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--authorization-plugin/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.12' do
  impact 0.7
  title '2.12 Configure centralized and remote logging (Scored)'
  desc '
    Docker now supports various log drivers. A preferable way to store logs is the one that
    supports centralized and remote logging.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.12', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe command("docker info --format '{{ .LoggingDriver }}' | grep 'json-file'" ) do
    its('stdout') { should be_empty }
  end
end

control 'cis-2.13' do
  impact 0.7
  title '2.13 Disable operations on legacy registry (v1) (Scored)'
  desc '
    The latest Docker registry is v2. All operations on the legacy registry version (v1) should be
    restricted.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.13', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--disable-legacy-registry/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.14' do
  impact 0.7
  title '2.14 Enable live restore (Scored)'
  desc '
    The ''--live-restore'' enables full support of daemon-less containers in docker. It ensures
    that docker does not stop containers on shutdown or restore and properly reconnects to
    the container when restarted.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.14', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--live-restore=true/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.15' do
  impact 0.7
  title '2.15 Do not enable swarm mode, if not needed (Scored)'
  desc '
    Do not enable swarm mode on a docker engine instance unless needed.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.15', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe command('docker info 2>/dev/null | grep -e "Swarm:*\sinactive\s*"') do
    its('stdout') { should_not be_empty }
  end
end

control 'cis-2.16' do
  impact 0.7
  title '2.16 Control the number of manager nodes in a swarm (Scored)'
  desc '
    Ensure that the minimum number of required manager nodes is created in a swarm.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.16', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker info 2>/dev/null | grep -e "Swarm:*\sinactive\s*"').stdout.empty?
  end

  describe command('docker node ls | grep -c "Leader"') do
    its('stdout.to_i') { should be <= 1 }
  end
end

control 'cis-2.17' do
  impact 0.7
  title '2.17 Bind swarm services to a specific host interface (Scored)'
  desc '
    By default, the docker swarm services will listen to all interfaces on the host, which may
    not be necessary for the operation of the swarm where the host has multiple network
    interfaces.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.17', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    !command('docker info 2>/dev/null | grep -e "Swarm:*\sactive\s*"').stdout.empty?
  end

  describe port(2377) do
    it { should be_listening }
    its('processes') { should eq ['dockerd'] }
    its('protocols') { should contain_match /tcp/ }
    its('addresses') { should_not include '0.0.0.0' }
  end
end

control 'cis-2.18' do
  impact 0.7
  title '2.18 Disable Userland Proxy (Scored)'
  desc '
    The docker daemon starts a userland proxy service for port forwarding whenever a port is
    exposed. Where hairpin NAT is available, this service is generally superfluous to
    requirements and can be disabled.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.18', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe processes('dockerd').where { command =~ /--userland-proxy=false/ } do
    its('entries') { should_not be_empty }
  end
end

control 'cis-2.19' do
  impact 0.7
  title '2.19 Encrypt data exchanged between containers on different nodes on the overlay network (Scored)'
  desc '
    Encrypt data exchanged between containers on different nodes on the overlay network.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.19', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    !command("docker network ls --filter driver=overlay --quiet | xargs docker network inspect --format '{{.Name}} {{ .Options }}' | grep -v 'encrypted:'").stdout.empty?
  end

  overlaynets = command("docker network ls --filter driver=overlay --quiet").stdout.split("\n")
  overlaynets.each do |encnet|
    describe command("docker network inspect --format '{{.Name}} {{ .Options }}' #{encnet} | grep -v 'encrypted:'") do
      its('stdout') { should be_empty }
    end
  end
end

control 'cis-2.20' do
  impact 0.7
  title '2.20 Apply a daemon-wide custom seccomp profile, if needed (Not Scored)'
  desc '
    You can choose to apply your custom seccomp profile at the daemon-wide level if needed
    and override Docker''s default seccomp profile.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.20', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    !command("docker info --format '{{ .SecurityOptions }}' | grep 'name=seccomp,profile=default'").stdout.empty?
  end

  describe command("docker info --format '{{ .SecurityOptions }}' | grep 'name=seccomp,profile=default'") do
    its('stdout') { should_not be_empty }
  end
end

control 'cis-2.21' do
  impact 0.7
  title '2.21 Avoid experimental features in production (Scored)'
  desc '
    Avoid experimental features in production.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.21', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe command('docker info | grep -e "Experimental:\s*false*"') do
    its('stdout') { should_not be_empty }
  end
end

control 'cis-2.22' do
  impact 0.7
  title '2.22 Use Docker''s secret management commands for managing secrets in a Swarm cluster (Not Scored)'
  desc '
    Use Docker''s in-built secret management command.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.22', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    !command('docker info | grep -e "Swarm:\s*active\s*"').stdout.empty? && command('docker secret ls -q | wc -l').stdout.to_i >= 1
  end

  describe command('docker secret ls -q | wc -l') do
    its('stdout.to_i') { should be >= 1 }
  end
end

control 'cis-2.23' do
  impact 0.7
  title '2.23 Run swarm manager in auto-lock mode (Scored)'
  desc '
    Run Docker swarm manager in auto-lock mode.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.23', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    !command('docker info | grep -e "Swarm:\s*active\s*"').stdout.empty?
  end

  describe command("docker swarm unlock-key | grep 'SWMKEY'") do
    its('stdout') { should_not be_empty }
  end
end

control 'cis-2.24' do
  impact 0.7
  title '2.24 Rotate swarm manager auto-lock key periodically (Not Scored)'
  desc '
    Rotate swarm manager auto-lock key periodically.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 2.24', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  puts "[NOTE]2.24 - Rotate swarm manager auto-lock key periodically"
end
