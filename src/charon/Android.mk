LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
charon.c

# build charon -----------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/libhydra \
	$(strongswan_PATH)/src/libcharon \
	$(strongswan_PATH)/src/libstrongswan

LOCAL_CFLAGS := $(strongswan_CFLAGS)

LOCAL_MODULE := charon

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan libhydra libcharon

include $(BUILD_EXECUTABLE)

