# FlowBreaker

## Using FlowBreaker
In order to use FlowBreaker, please refer to the documentation - from this
GitHub repo you will need the current release for your platform, either the Self
contained, or if you already have .NET 7 installed, the Framework
dependent release. FlowBreaker is a command line utility that relies on pcaps
being preprocessed with Zeek. Since Zeek itself is a bit of a hassle to set up,
below is a manual on how to run a webserver that handles all of this for you.

## Setting up FlowBreaker's Zeek Webserver with docker compose

## Deployment Instructions

The docker installation can be done by simply running the deploy_docker.sh script
using sudo or doas on your machine. This script will clone the repo and setup
the necessary permissions for the folders. You then only need to edit the paths
in the docker-compose.yml and can launch it by using "docker compose up".
Keep in mind that the setup scripts works relative to the current directory
when running it.

1. Download the deploy_docker.sh script from the repo

2. Run the script using sudo or doas

This script does the following:
   - Clones the FlowBreaker repository
   - Copies necessary files and folders (scripts, nginx, docker-compose.yml)
   - Creates required directories (uploads, zeek-logs, zipped-logs)
   - Sets the required permissions

3. Edit the `docker-compose.yml` file (see the "Configuration" section below)

4. Start the Docker containers after considering the configuration below.

5. Your installation should now be up at http://localhost:9005/upload.php and be able
   to process .pcaps and pcapngs for you.

6. (Optional) you can setup Nginx Proxy Manager to handle access controls and
    point it from yourdomain.com to (http) zeek-webserver-1 80
    By doing so, you can shield the container from the internet and have https.
    Make sure that npm and zeek-webserver-1 are in the same network for this to work.

## Configuration

Before running `docker compose up`, you need to modify the `docker-compose.yml` file:

1. Change the volume paths:
   Replace `/home/user/docker/zeek` with your desired path. For example:
  - /path/to/your/zeek/zeek-logs:/zeek-logs

2. (Optional) Change the exposed port:
  If you want to use a different port than 9005, modify the `ports` section of the `webserver` service:

3. (Optional) Configure access control:
   It's recommended to use a reverse proxy for access control instead of directly exposing port 80.
   This is to stop others from uploading potentially malicious files to your machine.

## Security Considerations

- The script sets directory permissions to 777 (read, write, execute for all).
  Consider using a more sophisticated approach, e.g. by named docker volumes.
  If the permissions aren't set, the shell scripts won't be able to write or
  detect file changes. It would be safer to circumvent this by fine tuning
  the permissions for cross-access by the containers.

- Using a reverse proxy is recommended for better security instead of directly exposing ports.
  A possibility would be nginx proxy manager, which also handles ssl.

## Services

The docker-compose file sets up the following services:

1. `zeek`: Runs the Zeek network analysis tool
2. `webserver`: Nginx web server for handling HTTP requests
3. `php`: PHP-FPM for processing PHP scripts
4. `zeek_manager`: Manages Zeek log processing and other tasks

## Known Issues

This setup isn't meant for multitasking. Uploading the next .pcap file before
the current has finished processed, should work in theory, but may lead to UI
bugs. There is also no concurrency in place, meaning that jobs finish in sequence.
Usually Zeek's analysis is very fast (2-3 seconds) and uploading and zipping take
the longest. If in doubt, restart the stack and try again.

## How does this stack work?

The Zeek image doesn't run perpetually without a command, so this stack keeps it
active. The zeek_manager.sh script watches for changes in the upload directory and
if it spots a new file, executes Zeek on it, using run_zeek_analysis.sh.
It then creates a new folder with the pcap's name and the current timestamp.
The CLI output of Zeek is saved to the console.log. The manager script watches for
this log file and after finding it, zips the contents of the folder, moves it to
zipped-logs and then deletes the original folder. This can be seen when looking
at the Docker logs. If you want to change the arguments Zeek is executed with,
change the run_zeek_analysis.sh script. In addition to this functionality, the
management script also deletes the oldest files from the upload folder once it
reaches 12GB. This is configurable in the script.

The upload.php script serves as the GUI that a ngnix webserver is serving. The
configuration of the nginx container is very basic, but has one feature that isn't
intuitive: If you hit localhost:9005 you will be redirected.
Why? Because that way when you setup a reverse proxy, you don't need to bother
with people typing out the /upload.php part. Instead, when they hit yourdomain.com
they will be redirected to yourdomain.com/upload.php. This setup only works when
using a reverse proxy however, not when accessing the port directly.

The php server is used for executing the upload.php file when it's served to a
user. The page auto refreshes internally every 5 seconds to check for new zipped
log files to display.

This is a simplification of the shell scripts, meant to provide an overview.
