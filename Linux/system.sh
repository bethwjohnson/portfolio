#!/bin/bash

# prints ammount of free memory and saves to free_mem.txt

free -h > ~/backups/freemem/free_mem.txt

# prints disk usage and saves to disk_usage.txt

du -h > ~/backups/diskuse/disk_usage.txt

# lists all open files and saves to open_lists.txt

ps -aux > ~/backups/openlist/open_list.txt

# prints file system disk space statistics and saves to free_disk.txt

df -h > ~/backups/freedisk/free_disk.txt