# Tasks Template

Define a Task Image for Run by Opencomply Platform. User Can Define a Task Image and Run it on Opencomply Platform.
You can fork this repository and create your own task image.

## Task Definition

Task is a set of instructions that can be executed by Opencomply Platform.
It should be run once every time it is executed. And have an output that can be written to a file.

Defining a task has one main parts:

### 1. Code

First part is the code that will be executed. It can be a shell script, python script, or any other executable file.
We Use [task.sh](worker/task.sh) as an example.

```shell
#!/bin/bash
echo "Hello World"
echo "This is an example task"
```

### 2. Build Image

Second part is the Dockerfile that will be used to build the task image.
You can use any base image you want, but it should have the necessary tools to run the go code.
Also If you want you can install additional tools or libraries.

```dockerfile
# Do not change the code below
# Run The Sender Go Application
FROM golang:1.23-alpine 
# Copy the source code
COPY . .
# Download the dependencies
RUN cd sender && go mod download -x
# Build the Go application
RUN cd sender &&   go build -o task .

ENTRYPOINT ["./sender/task"]
```

We use [Dockerfile](./Dockerfile) for Building Image.

