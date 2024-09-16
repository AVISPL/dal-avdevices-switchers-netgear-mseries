/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi.data;

import java.util.HashMap;
import java.util.Map;

/**
 * Constants container. Includes property values maps for values matching purposes,
 * URIs, Property names, json paths used, etc.
 * */
public class Constants {
    public static final Map<String, String> FAN_STATE_VALUES = new HashMap<>();
    public static final Map<String, String> FAN_MODE_VALUES = new HashMap<>();
    public static final Map<String, String> LINK_STATE_VALUES = new HashMap<>();
    public static final Map<String, String> SENSOR_STATE_VALUES = new HashMap<>();
    public static final Map<String, String> ADMIN_STATE_VALUES = new HashMap<>();

    public static final Map<String, String> MODULE_TYPE_VALUES = new HashMap<>();
    public static final Map<String, String> PORT_MODE_VALUES = new HashMap<>();
    public static final Map<String, String> PORT_STATE_VALUES = new HashMap<>();
    public static final Map<String, String> STP_MODE_VALUES = new HashMap<>();
    public static final Map<String, String> AUTO_TRUNK_VALUES = new HashMap<>();
    public static final Map<String, String> POE_IS_VALID_VALUES = new HashMap<>();

    public static final Map<String, String> POE_POWER_MODE_VALUES = new HashMap<>();
    public static final Map<String, String> POE_DETECTION_TYPE_VALUES = new HashMap<>();
    public static final Map<String, String> POE_PRIORITY_VALUES = new HashMap<>();
    public static final Map<String, String> POE_POWER_LIMIT_MODE_VALUES = new HashMap<>();
    public static final Map<String, String> POE_CLASSIFICATION_VALUES = new HashMap<>();
    public static final Map<String, String> POE_STATUS_VALUES = new HashMap<>();

    public static final Map<String, String> PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES = new HashMap<>();

    static {
        FAN_STATE_VALUES.put("0","ACTIVE");
        FAN_STATE_VALUES.put("1","INACTIVE");

        FAN_MODE_VALUES.put("1","OFF");
        FAN_MODE_VALUES.put("2","QUIET");
        FAN_MODE_VALUES.put("3","COOL");

        LINK_STATE_VALUES.put("0","UP");
        LINK_STATE_VALUES.put("1","DOWN");

        SENSOR_STATE_VALUES.put("0","NONE");
        SENSOR_STATE_VALUES.put("1","NORMAL");
        SENSOR_STATE_VALUES.put("2","WARNING");
        SENSOR_STATE_VALUES.put("3","CRITICAL");
        SENSOR_STATE_VALUES.put("4","SHUTDOWN");
        SENSOR_STATE_VALUES.put("5","NOT_PRESENT");
        SENSOR_STATE_VALUES.put("6","NOT_OPERATIONAL");

        ADMIN_STATE_VALUES.put("0","DISABLE");
        ADMIN_STATE_VALUES.put("1","ENABLE");

        MODULE_TYPE_VALUES.put("0","NONE");
        MODULE_TYPE_VALUES.put("1","SFP");
        MODULE_TYPE_VALUES.put("2","SFP+");
        MODULE_TYPE_VALUES.put("3","QSFP");
        MODULE_TYPE_VALUES.put("4","Direct Attach Cable");
        MODULE_TYPE_VALUES.put("5","XFP, AX741, 10G plugin module");
        MODULE_TYPE_VALUES.put("6","Stacking module, AX742");
        MODULE_TYPE_VALUES.put("7","SFP+ plugin module, AX743");
        MODULE_TYPE_VALUES.put("8","CX4 plugin module, AX744");
        MODULE_TYPE_VALUES.put("9","Copper 10G plugin module, AX745");
        MODULE_TYPE_VALUES.put("10","HDMI");

        PORT_MODE_VALUES.put("0","MODE_NONE");
        PORT_MODE_VALUES.put("1","MODE_GENERAL");
        PORT_MODE_VALUES.put("2","MODE_ACCESS");
        PORT_MODE_VALUES.put("3","MODE_TRUNK");
        PORT_MODE_VALUES.put("4","MODE_PRIVATE_HOST");
        PORT_MODE_VALUES.put("5","MODE_PRIVATE_PROMISC");

        PORT_STATE_VALUES.put("0","OPEN_PORT_DISABLE");
        PORT_STATE_VALUES.put("1","OPEN_PORT_ENABLE");
        PORT_STATE_VALUES.put("2","OPEN_PORT_DIAG_DISABLE");

        STP_MODE_VALUES.put("0","STP");
        STP_MODE_VALUES.put("1","Unused");
        STP_MODE_VALUES.put("2","RSTP");
        STP_MODE_VALUES.put("3","MST");

        AUTO_TRUNK_VALUES.put("0","Disabled");
        AUTO_TRUNK_VALUES.put("1","Enabled");

        POE_IS_VALID_VALUES.put("1","PoE");
        POE_IS_VALID_VALUES.put("2","PoE Plus");
        POE_IS_VALID_VALUES.put("3","PSE");
        POE_IS_VALID_VALUES.put("4","PSE Plus");
        POE_IS_VALID_VALUES.put("5","PD");
        POE_IS_VALID_VALUES.put("6","PD Plus");
        POE_IS_VALID_VALUES.put("7","UPoE");

        POE_POWER_MODE_VALUES.put("0", "802.3AF");
        POE_POWER_MODE_VALUES.put("1", "HIGH_INRUSH");
        POE_POWER_MODE_VALUES.put("2", "PRE_802.3AT");
        POE_POWER_MODE_VALUES.put("3", "802.3AT");
        POE_POWER_MODE_VALUES.put("4", "802.3BT/UPOE");

        POE_DETECTION_TYPE_VALUES.put("1", "LEGACY");
        POE_DETECTION_TYPE_VALUES.put("2", "4PT_DOT3AF");
        POE_DETECTION_TYPE_VALUES.put("3", "4PT_DOT3AF_LEG");
        POE_DETECTION_TYPE_VALUES.put("4", "2PT_DOT3AF");
        POE_DETECTION_TYPE_VALUES.put("5", "2PT_DOT3AF_LEG");

        POE_PRIORITY_VALUES.put("1", "LOW");
        POE_PRIORITY_VALUES.put("2", "MEDIUM");
        POE_PRIORITY_VALUES.put("3", "HIGH");
        POE_PRIORITY_VALUES.put("4", "CRITICAL");

        POE_POWER_LIMIT_MODE_VALUES.put("1", "CLASS");
        POE_POWER_LIMIT_MODE_VALUES.put("2", "USER");
        POE_POWER_LIMIT_MODE_VALUES.put("3", "NONE");

        POE_CLASSIFICATION_VALUES.put("0", "INVALID");
        POE_CLASSIFICATION_VALUES.put("1", "CLASS_0");
        POE_CLASSIFICATION_VALUES.put("2", "CLASS_1");
        POE_CLASSIFICATION_VALUES.put("3", "CLASS_2");
        POE_CLASSIFICATION_VALUES.put("4", "CLASS_3");
        POE_CLASSIFICATION_VALUES.put("5", "CLASS_4");

        POE_STATUS_VALUES.put("0", "DISABLED");
        POE_STATUS_VALUES.put("1", "SEARCHING");
        POE_STATUS_VALUES.put("2", "SEARCHING");
        POE_STATUS_VALUES.put("3", "FAULT");

        PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES.put("Enable", "enable");
        PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES.put("PowerLimitMode", "powerLimitMode");
        PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES.put("PowerLimit(mW)", "powerLimit");
        PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES.put("DetectionType", "detectionType");
        PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES.put("Priority", "priority");
        PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES.put("PowerMode", "powerMode");
    }

    /**
     * URIs used for data retrieval
     * */
    public interface URI {
        String BASE_URI = "/api/v1/";
        String LOGIN = "login";
        String DEVICE_INFO = "device_info";
        String POE_PORTS_CFG = "swcfg_poe?port=all";
        String VLAN_INFO = "vlan";
        String POE_CFG = "swcfg_poe";
        String DEVICE_POWER = "device_power";
        String DEVICE_FAN = "device_fan";
        String PORTS_CFG = "swcfg_port?portid=all";
        String PORTS_STATUS = "swcfg_ports_status?indexPage=1&pageSize=9999";
        String NEIGHBOR_STATUS = "neighbor?indexPage=1&pageSize=99999";
        String PORT_IN_STATISTICS = "port_statistics?type=inbound%indexPage=1&pageSize=5";
        String PORT_OUT_STATISTICS = "port_statistics?type=outbound&indexPage=1&pageSize=5";
    }

    /**
     * Device property names
     * */
    public interface Properties {
        String REBOOT = "Reboot";
        String FAN_MODE = "FanMode";
        String ADAPTER_VERSION = "AdapterVersion";
        String ADAPTER_BUILD_DATE = "AdapterBuildDate";
        String ADAPTER_UPTIME = "AdapterUptime";
        String DEVICE_INFO = "DeviceInfo";
        String UNIT_NUMBER = "UnitNumber";
        String SERIAL_NUMBER = "SerialNumber";
        String MODEL = "Model";
        String ACTIVE = "Active";
        String SWITCHERS = "Switchers";
        String AV_DEVICES = "AV Devices";
        String MANAGEMENT = "Management";
        String FW_VERSION = "FirmwareVersion";
        String BOOT_VERSION = "BootVersion";
        String UPTIME = "Uptime(h)";
        String UPTIME_RAW = "Uptime";
        String DESCRIPTION = "Description";
        String FAN_N_GROUP = "Fan_%s#";
        String SENSOR_N_GROUP = "Sensor_%s#";
        String PORT_N_POE_GROUP = "Port00_%02d_POEConfiguration#";
        String PORT_N_GENERAL_INFORMATION_GROUP = "Port%s_GeneralInformation#";
        String PORT_N_NEIGHBOR_INFORMATION_N_GROUP = "Port%s_NeighborInformation_%02d#";
        String PORT_N_STATISTICS_N_GROUP = "Port%s_Statistics#%s";
        String STATE = "State";
        String MEMORY_USAGE = "MemoryUsage(%)";
        String ADMIN_STATE = "AdminState";
        String LINK_STATE = "LinkState";
        String PORT_STRING = "PortString";
        String PORT_NUMBER = "PortNumber";
        String ENABLE = "Enable";
        String POWER_LIMIT_MODE = "PowerLimitMode";
        String CLASSIFICATION = "Classification";
        String POWER_LIMIT = "PowerLimit";
        String DETECTION_TYPE = "DetectionType";
        String PRIORITY = "Priority";
        String POWER_MODE = "PowerMode";
        String MODULE_TYPE = "ModuleType";
        String PORT_MODE = "PortMode";
        String PORT_STATE = "PortState";
        String STP_MODE = "STPMode";
        String AUTO_TRUNK = "AutoTrunk";
        String IS_VALID = "IsValid";
        String UNIT_ID = "UnitID";
    }

    /**
     * yml mapper models, to ease out the properties mapping process
     * */
    public interface MapperModels {
        String DEVICE_DETAILS_UNIT_INFO = "DeviceDetailsUnitInfo";
        String DEVICE_UNIT_FAN_INFO = "DeviceUnitFanInfo";
        String DEVICE_UNIT_SENSOR_INFO = "DeviceUnitSensorInfo";
        String UNIT_PORT_INFO = "UnitPort";
        String PORT_POE_INFORMATION = "PortPOEInformation";
        String PORT_CONFIGURATION_INFORMATION = "PortConfiguration";
        String NEIGHBOR_INFORMATION = "NeighborInformation";
        String IN_PORT_STATISTICS = "InPortStatistics";
        String OUT_PORT_STATISTICS = "OutPortStatistics";
    }

    /**
     * Property group entries that provide property group filtering
     * */
    public interface PropertyGroupEntries {
        String PORT_GENERAL_INFORMATION = "PortGeneralInformation";
        String POE_INFORMATION = "POEInformation";
        String PORT_CONFIGURATION_INFORMATION = "PortConfigurationInformation";
        String PORT_NEIGHBOR_INFORMATION = "PortNeighborInformation";
        String PORT_INBOUND_INFORMATION = "PortInboundStatistics";
        String PORT_OUTBOUND_INFORMATION = "PortOutboundStatistics";
    }

    /**
     * Json properties for control operations
     * */
    public interface JsonProperties {
        String NAME = "name";
        String PASSWORD = "password";
        String USER = "user";
        String LAG = "lag";
        String POWER = "power";
        String TYPE = "type";
        String REBOOT = "reboot";
        String SAVE = "save";
        String FAN_MODE = "fanMode";
        String UNIT = "unit";
        String PORT_N = "portNum";
        String PORT = "port";
        String POE_PORT_CONFIG = "poePortConfig";
        String ENABLE = "enable";
    }

    /**
     * Json paths used for data retrieval
     * */
    public interface JsonPaths {
        String DEVICE_INFO_DETAILS = "/deviceInfo/details";
        String DEVICE_INFO_FAN = "/deviceInfo/fan";
        String DEVICE_INFO_SENSOR = "/deviceInfo/sensor";
        String DEVICE_INFO_CPU = "/deviceInfo/cpu";
        String DEVICE_INFO_MEMORY = "/deviceInfo/memory";
        String USER_SESSION = "/user/session";
        String UNIT = "/unit";
        String DETAILS = "/details";
        String USAGE = "/usage";
        String SWITCH_PORT_STATUS_ROWS = "/switchPortStatus/rows";
        String PORT_STRING = "/portStr";
        String POE_PORT_CONFIG = "/poePortConfig";
        String SWITCH_PORT_CONFIG_UNIT = "/switchPortConfig/unit";
        String ID = "/id";
        String SLOT_0_PORT = "/slot/0/port";
        String LLDP_REMOTE_DEVICE_ROWS = "/lldpRemoteDevice/rows";
        String PORT_STATISTICS_ROWS = "/portStatistics/rows";
        String PORT_NAME = "/portName";
    }

    /**
     * Miscellaneous constants (special characters, default values, etc.)
     * */
    public interface Misc {
        String HASH = "#";
        String PCT = "%";
        String TRUE = "true";
        String PORT_NUMBER_TEMPLATE = "%02d_%02d";
        String PORT_NUMBER_TEMPLATE_REGEX = "(\\d+)\\/(\\d+)$";
        String PORT_NUMBER_TEMPLATE_EXTRACT_REGEX = "(\\d{2})_(\\d{2})";
    }
}
