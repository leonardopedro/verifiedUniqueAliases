Vagrant.configure("2") do |config|
  # Use the Oracle Linux 10 box
  config.vm.box = "OracleLinux10"
  
  # Use libvirt provider
  config.vm.provider "libvirt" do |libvirt|
    libvirt.memory = 6144
    libvirt.cpus = 4
    libvirt.driver = "kvm"
    libvirt.serial :type => 'file', :path => 'serial.log'
  end
  
  # Use default rsync synced folder
  config.vm.synced_folder ".", "/vagrant", type: "rsync"
end
