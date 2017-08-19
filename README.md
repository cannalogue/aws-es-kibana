Set AWS credentials
                          
    export AWS_ACCESS_KEY_ID=XXXXXXXXXXXXXXXXXXX
    export AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXX

### Run within docker container

If you are familiar with Docker, you can run `aws-es-kibana` within a Docker container

Build the image

	docker build -t aws-es-kibana .

Run the container (do not forget to pass the required environment variables)

	docker run -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -p 127.0.0.1:9200:9200 aws-es-kibana -b 0.0.0.0 <cluster-endpoint>