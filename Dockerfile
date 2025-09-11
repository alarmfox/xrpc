FROM ubuntu:24.04
RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential make valgrind --no-install-recommends
