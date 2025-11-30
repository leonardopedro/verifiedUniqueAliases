Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant", type: "rsync"
  config.vm.provider :libvirt do |libvirt|
    libvirt.driver = "kvm"
  end
end