ANDROID_API_LEVEL ?= 19
ANDROID_SDK_ROOT ?= $(shell echo ~/Android/Sdk)

android_platform := android-$(ANDROID_API_LEVEL)
android_jar := $(ANDROID_SDK_ROOT)/platforms/$(android_platform)/android.jar

helper.dex: build/miru-helper.jar
	d8 \
		--classpath $(android_jar) \
		--output build/ \
		$<
	mv build/classes.dex $@

build/miru-helper.jar: re/miru/Helper.java
	javac \
		-cp .:$(android_jar) \
		-bootclasspath $(android_jar) \
		-source 1.8 \
		-target 1.8 \
		-Xlint:deprecation \
		-Xlint:unchecked \
		$^ \
		-d build/java/
	jar cfe $@ re.miru.Helper -C build/java/ .
