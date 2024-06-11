#!/bin/bash

# Set the path to the kernel source directory
KERNEL_DIR="/home/osboxes/RootAsLSM/kernelbuild/linux-6.8.7"

# Set the desired kernel version
# KERNEL_VERSION="x.x.x"

# Change to the kernel source directory
cd $KERNEL_DIR

# Clean the kernel source directory
# make clean

# Configure the kernel
# make menuconfig

# Build the kernel
make -j$(nproc)

# Install the kernel modules
# make modules

# Install the kernel
# make modules_install

# Update the bootloader configuration
# update-grub

# Copy the bzImage to the boot directory
cp -v arch/x86/boot/bzImage /boot/vmlinuz-linux68

# Choose the right entry for the bootloader
# sudo grub-reboot "Arch Linux, with Linux linux68"

# Reboot the system to load the new kernel
reboot