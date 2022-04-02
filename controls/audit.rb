# frozen_string_literal: true

# copyright:: 2015, The Authors
# license: All rights reserved

title 'audit section'

control 'audit-1.0' do # A unique ID for this control
  impact 0.7 # The criticality, if this control fails.
  title 'auditd should be present'
  desc 'Ensure auditd executable and configuration are present'
  only_if { !(virtualization.role == 'guest' && (virtualization.system == 'docker' || virtualization.system == 'lxd')) }
  if os.darwin?
    describe file('/etc/security/audit_control') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0400' }
      its('content') { should match 'flags:' }
      its('content') { should match 'policy:cnt,argv' }
      its('content') { should match 'superuser-set-sflags-mask:' }
    end
  else
    describe file('/etc/audit') do
      it { should be_directory }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0750' }
    end
    describe file('/etc/audit/auditd.conf') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0640' }
    end
    describe file('/etc/audit/audit.rules') do
      it { should be_file }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0640' }
    end
  end
  describe file('/usr/sbin/auditd') do
    it { should be_file }
    it { should be_executable }
    it { should be_owned_by 'root' }
  end
end

control 'audit-2.0' do
  impact 0.7
  title 'auditd should be running'
  desc 'Ensure auditd is running'
  only_if { !(virtualization.role == 'guest' && (virtualization.system == 'docker' || virtualization.system == 'lxd')) }
  unless os.darwin?
    describe processes('auditd') do
      its('users') { should eq ['root'] }
      its('list.length') { should eq 1 }
    end
  end
end

control 'audit-3.0' do
  impact 0.7
  title 'auditd should have log files'
  desc 'Ensure auditd logs file are present'
  only_if { !(virtualization.role == 'guest' && (virtualization.system == 'docker' || virtualization.system == 'lxd')) }
  if os.darwin?
    describe file('/var/audit') do
      it { should be_directory }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0700' }
    end
    describe file('/var/audit/current') do
      it { should be_symlink }
      it { should be_owned_by 'root' }
      its('mode') { should cmp '0440' }
    end
  end
end

control 'audit-4.0' do
  impact 0.7
  title 'auditd updated log files'
  desc 'Ensure auditd logs file were updated less than 900s in the past'
  only_if { !(virtualization.role == 'guest' && (virtualization.system == 'docker' || virtualization.system == 'lxd')) }
  describe file('/var/audit/current').mtime.to_i do
    it { should <= Time.now.to_i }
    it { should >= Time.now.to_i - 900 }
  end
end
