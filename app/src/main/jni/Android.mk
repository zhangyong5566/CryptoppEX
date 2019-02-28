LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_LDLIBS 	:= -ljnigraphics -llog -lz -latomic -lOpenSLES -lEGL -lGLESv2 -landroid

LOCAL_STATIC_LIBRARIES := cpufeatures
ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
    LOCAL_CPPFLAGS  := -march=armv8-a+crc+crypto
endif
ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_ARM_NEON := true
    LOCAL_CPPFLAGS := -march=armv7-a -DHAVE_NEON=1
endif
ifeq ($(TARGET_ARCH),x86)
    LOCAL_CPPFLAGS := -mssse3 -msse4.2 -mpclmul -maes -msha
endif
ifeq ($(TARGET_ARCH),x86_64)
    LOCAL_CPPFLAGS := -mssse3 -msse4.2 -mpclmul -maes -msha
endif
LOCAL_CFLAGS := -DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSSE3 -DCRYPTOPP_DISABLE_AESNI
FILE_LIST = $(wildcard $(LOCAL_PATH)/cryptopp/*.cpp)
LOCAL_SRC_FILES := $(FILE_LIST:$(LOCAL_PATH)/%=%)
LOCAL_MODULE := native-lib
include $(BUILD_SHARED_LIBRARY)
$(call import-module, android/cpufeatures)
