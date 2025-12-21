FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV PATH="$PATH:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools"

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    unzip \
    git \
    maven \
    gradle \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p $ANDROID_SDK_ROOT/cmdline-tools
RUN curl -fsSL https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -o /tmp/cmdline.zip \
  && unzip -q /tmp/cmdline.zip -d $ANDROID_SDK_ROOT/cmdline-tools \
  && mv $ANDROID_SDK_ROOT/cmdline-tools/cmdline-tools $ANDROID_SDK_ROOT/cmdline-tools/latest \
  && rm /tmp/cmdline.zip

ARG ANDROID_API_MIN=25
ARG ANDROID_API_MAX=36
RUN yes | sdkmanager --licenses
RUN for api in $(seq ${ANDROID_API_MIN} ${ANDROID_API_MAX}); do \\
      sdkmanager "platforms;android-${api}"; \\
    done \\
  && sdkmanager "platform-tools"

WORKDIR /workspace
CMD ["/bin/bash"]
