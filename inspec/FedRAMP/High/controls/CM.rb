# encoding: utf-8
# copyright: 2017 Docker, Inc.
# license: Apache 2.0

title 'CM - Configuration Management'

include_controls 'docker-ee-fedramp-moderate'

control 'CM-2 (2)' do
    impact 1.0
    title 'CM-2 (2) BASELINE CONFIGURATION | AUTOMATION SUPPORT FOR ACCURACY / CURRENCY'
    desc '    
        The organization employs automated mechanisms to maintain an up-to-date,
        complete, accurate, and readily available baseline configuration of the
        information system.
    '
    ref 'CM-2 (2) BASELINE CONFIGURATION | AUTOMATION SUPPORT FOR ACCURACY / CURRENCY', url: 'https://nvd.nist.gov/800-53/Rev4/control/CM-2#enhancement-2'

    # describe command('echo hello') do
    #     its('stdout') { should eq "hello\n" }
    # end
end
    