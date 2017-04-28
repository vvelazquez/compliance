# encoding: utf-8
# copyright: 2017 Docker, Inc.
# license: Apache 2.0

title 'CM - Configuration Management'

include_controls 'cis-docker-benchmark'

control 'CM-2-Moderate' do
    impact 1.0
    title 'CM-2 Baseline Configuration'
    desc '    
        The organization develops, documents, and maintains under configuration
        control, a current baseline configuration of the information system.
    '
    ref 'CM-2 Baseline Configuration', url: 'https://nvd.nist.gov/800-53/Rev4/control/CM-2'

    # describe command('echo hello') do
    #     its('stdout') { should eq "hello\n" }
    # end
end