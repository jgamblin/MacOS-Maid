#!/bin/bash
SECONDS=3600

#Install Updates.
printf "Installing needed updates.\n"
softwareupdate -i -a > /dev/null 2>&1

#Taking out the trash.
printf "Emptying the trash.\n"
sudo rm -rfv /Volumes/*/.Trashes > /dev/null 2>&1
sudo rm -rfv ~/.Trash  > /dev/null 2>&1

#Clean the logs.
printf "Emptying the system log files.\n"
sudo rm -rfv /private/var/log/*  > /dev/null 2>&1
sudo rm -rfv /Library/Logs/DiagnosticReports/* > /dev/null 2>&1

printf "Deleting the quicklook files.\n"
sudo rm -rf /private/var/folders/ > /dev/null 2>&1

#Cleaning Up Homebrew.
printf "Cleaning up Homebrew.\n"
brew cleanup --force -s > /dev/null 2>&1
brew cask cleanup > /dev/null 2>&1
rm -rfv /Library/Caches/Homebrew/* > /dev/null 2>&1
brew tap --repair > /dev/null 2>&1

#Cleaning Up Ruby.
printf "Cleanup up Ruby.\n"
gem cleanup > /dev/null 2>&1

#Cleaning Up Docker.
#You May Not Want To Do This.
printf "Removing all Docker containers.\n"
docker rmi -f "$(docker images -q --filter 'dangling=true')" > /dev/null 2>&1

#Purging Memory.
printf "Purging Memory.\n"
sudo purge > /dev/null 2>&1

#Securly Erasing Data.
printf "Securely erasing free space (This will take a while). \n"
diskutil secureErase freespace 0 "$( df -h / | tail -n 1 | awk '{print $1}')" > /dev/null 2>&1

#Finishing Up.
timed="$((SECONDS / 3600)) Hours $(((SECONDS / 60) % 60)) Minutes $((SECONDS % 60)) seconds"

printf "Maid Service Took %s this time. Dont Forget To Tip!\n" "$timed"
