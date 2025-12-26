FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV PYTHONPATH="/workspace/src"
ENV PATH="/opt/jadx/bin:/opt/gradle/bin:$PATH:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools"

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    python3-venv \
    python-is-python3 \
    curl \
    unzip \
    git \
    maven \
    ca-certificates \
    graphviz \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt

ARG GRADLE_VERSION=8.7
RUN curl -fsSL https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip -o /tmp/gradle.zip \
  && unzip -q /tmp/gradle.zip -d /opt \
  && ln -s /opt/gradle-${GRADLE_VERSION} /opt/gradle \
  && rm /tmp/gradle.zip

ARG JADX_VERSION=1.5.1
RUN mkdir -p /opt/jadx \
  && curl -fsSL https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip -o /tmp/jadx.zip \
  && unzip -q /tmp/jadx.zip -d /opt/jadx \
  && chmod +x /opt/jadx/bin/jadx \
  && rm /tmp/jadx.zip

RUN mkdir -p $ANDROID_SDK_ROOT/cmdline-tools
RUN curl -fsSL https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -o /tmp/cmdline.zip \
  && unzip -q /tmp/cmdline.zip -d $ANDROID_SDK_ROOT/cmdline-tools \
  && mv $ANDROID_SDK_ROOT/cmdline-tools/cmdline-tools $ANDROID_SDK_ROOT/cmdline-tools/latest \
  && rm /tmp/cmdline.zip

RUN yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --licenses
RUN /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=${ANDROID_SDK_ROOT} \
  "platforms;android-25" \
  "platforms;android-26" \
  "platforms;android-27" \
  "platforms;android-28" \
  "platforms;android-29" \
  "platforms;android-30" \
  "platforms;android-31" \
  "platforms;android-32" \
  "platforms;android-33" \
  "platforms;android-34" \
  "platforms;android-35" \
  "platforms;android-36" \
  "platform-tools"

WORKDIR /workspace
CMD ["/bin/bash"]
