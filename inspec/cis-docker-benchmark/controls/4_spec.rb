# encoding: utf-8
# copyright: 2017 Docker, Inc
# license: Apache 2.0

title '4 Container Images and Build File'

control 'cis-4.1' do
  impact 0.7
  title '4.1 Create a user for the container (Scored)'
  desc '
    Create a non-root user for the container in the Dockerfile for the container image.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.1', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker ps --quiet --all').stdout.split("\n").count > 0
  end

  containers = command('docker ps --quiet --all').stdout.split("\n")
  containers.each do |container|
    describe command("docker inspect --format '{{ .Id }}: User={{ .Config.User }}' #{container}") do
        its('stdout') { should_not match /User=$/ }
        its('stdout') { should_not match /User=\[\]/ }
        its('stdout') { should_not match /User=\<no value\>/ }
    end
  end
end

control 'cis-4.2' do
  impact 0.7
  title '4.2 Use trusted base images for containers (Not Scored)'
  desc '
    Ensure that the container image is written either from scratch or is based on another
    established and trusted base image downloaded over a secure channel.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.2', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  puts "[NOTE]4.2  - Use trusted base images for containers"
end

control 'cis-4.3' do
  impact 0.7
  title '4.3 Do not install unnecessary packages in the container (Not Scored)'
  desc '
    Containers tend to be minimal and slim down versions of the Operating System. Do not
    install anything that does not justify the purpose of container.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.3', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  puts "[NOTE]4.3  - Do not install unnecessary packages in the container"
end

control 'cis-4.4' do
  impact 0.7
  title '4.4 Scan and rebuild images to include security packages (Not Scored)'
  desc '
    Images should be scanned "frequently" for any vulnerabilities. Rebuild the images to
    include patches and then instantiate new containers from it.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.4', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  puts "[NOTE]4.4  - Scan and rebuild the images to include security patches"
end

control 'cis-4.5' do
  impact 0.7
  title '4.5 Enable Content trust for Docker (Scored)'
  desc '
    Content trust is disabled by default. You should enable it.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.5', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  describe os_env('DOCKER_CONTENT_TRUST') do
    its('content') { should eq '1' }
  end
end

control 'cis-4.6' do
  impact 0.7
  title '4.6 Add HEALTHCHECK instruction to the container image (Scored)'
  desc '
    Add HEALTHCHECK instruction in your docker container images to perform the health check
    on running containers.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.6', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker images -q').stdout.split("\n").count > 0
  end

  images = command("docker images | sed '1d' | awk '{print $1}'").stdout.split("\n")
  images.each do |image|
    describe command("docker inspect --format='{{.Config.Healthcheck}}' #{image} | grep -e '<nil>'") do
      its('stdout') { should be_empty }
    end

    # Not sure how this check is supposed to work per docker-bench-security script
    #
    # describe command("docker inspect --format='{{.RepoTags}}' #{image}") do
    #   its('stdout') { should_not eq '[]' }    
    # end
  end
end

control 'cis-4.7' do
  impact 0.7
  title '4.7 Do not use update instructions alone in the Dockerfile (Not Scored)'
  desc '
    Do not use update instructions such as apt-get update alone or in a single line in the
    Dockerfile.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.7', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker images -q').stdout.split("\n").count > 0
  end

  images = command("docker images | sed '1d' | awk '{print $1}'").stdout.split("\n")
  images.each do |image|
    describe command("docker history #{image} | grep -e 'update'") do
      its('stdout') { should be_empty }
    end

    # Not sure how this check is supposed to work per docker-bench-security script
    # describe command("docker inspect --format='{{.RepoTags}}' #{image}") do
    #  its('stdout') { should_not eq '[]' }    
    # end
  end
end

control 'cis-4.8' do
  impact 0.7
  title '4.8 Remove setuid and setgid permissions in the images (Not Scored)'
  desc '
    Removing setuid and setgid permissions in the images would prevent privilege escalation
    attacks in the containers.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.8', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker images -q').stdout.split("\n").count > 0
  end

  puts "[NOTE]4.8  - Remove setuid and setgid permissions in the images"
end

control 'cis-4.9' do
  impact 0.7
  title '4.9 Use COPY instead of ADD in Dockerfile (Not Scored)'
  desc '
    Use COPY instruction instead of ADD instruction in the Dockerfile.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.9', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker images -q').stdout.split("\n").count > 0
  end

  images = command("docker images | sed '1d' | awk '{print $1}'").stdout.split("\n")
  images.each do |image|
    describe command("docker history #{image} | grep 'ADD'") do
      its('stdout') { should be_empty }
    end

    # Not sure how this check is supposed to work per docker-bench-security script
    # describe command("docker inspect --format='{{.RepoTags}}' #{image}") do
    #   its('stdout') { should_not eq '[]' }    
    # end
  end
end

control 'cis-4.10' do
  impact 0.7
  title '4.10 Do not store secrets in Dockerfiles (Not Scored)'
  desc '
    Do not store any secrets in Dockerfiles.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.10', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker images -q').stdout.split("\n").count > 0
  end

  puts "[NOTE]4.10  - Do not store secrets in Dockerfiles"
end

control 'cis-4.11' do
  impact 0.7
  title '4.11 Install verified packages only (Not Scored)'
  desc '
    Verify authenticity of the packages before installing them in the image.
  '
  ref 'CIS Docker 1.13.0 Benchmark - Section 4.11', url: 'https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.13.0_Benchmark_v1.0.0.pdf'

  only_if do
    command('docker images -q').stdout.split("\n").count > 0
  end

  puts "[NOTE]4.11  - Install verified packages only\n\n"
end
