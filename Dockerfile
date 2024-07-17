# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Install cron
RUN apt-get update && apt-get install -y cron

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the important directory contents into the container at /usr/src/app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Add the crontab file to the cron directory
ADD crontab /etc/cron.d/simple-cron

# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/simple-cron

# Apply the cron job
RUN crontab /etc/cron.d/simple-cron

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

# Run the command on container startup
CMD cron && tail -f /var/log/cron.log