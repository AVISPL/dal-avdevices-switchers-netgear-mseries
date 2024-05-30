/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi;

import com.avispl.symphony.api.dal.dto.control.ControllableProperty;
import com.avispl.symphony.api.dal.dto.monitor.ExtendedStatistics;
import com.avispl.symphony.api.dal.dto.monitor.GenericStatistics;
import com.avispl.symphony.api.dal.dto.monitor.Statistics;
import com.avispl.symphony.api.dal.dto.monitor.aggregator.AggregatedDevice;
import com.avispl.symphony.api.dal.error.ResourceNotReachableException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.util.Assert;

import java.util.List;

/**
 * Netgear AV over IP tests
 *
 * @author Maksym.Rossiytsev/AVISPL Team
 * */
public class NetgearAVAPICommunicatorTest {
    static NetgearAVAPICommunicator communicator;

    @BeforeAll
    public static void setUp() throws Exception {
        communicator = new NetgearAVAPICommunicator();
        communicator.setHost("10.30.30.103");
        communicator.setProtocol("http");
        communicator.setPort(80);
        communicator.setLogin("");
        communicator.setPassword("");
        communicator.init();
    }

    @Test
    public void testGetMultipleStatisticsStack() throws Exception {
        communicator.setIncludePropertyGroups("PortGeneralInformation, PortConfigurationInformation, PortNeighborInformation, POEInformation, PortInboundStatistics, PortOutboundStatistics");
        communicator.setMonitoringMode("Stack");
        communicator.setManagementUnitSerialNumber("74W12C57F000F");
        List<Statistics> statisticsList = communicator.getMultipleStatistics();
        List<AggregatedDevice> units = communicator.retrieveMultipleStatistics();
        Assert.isTrue(((ExtendedStatistics)statisticsList.get(0)).getStatistics().isEmpty(), "Device multiple statistics should be empty");
        Assert.isTrue(!units.isEmpty(), "Aggregated devices list shouldn't be empty");
    }

    @Test
    public void testGetMultipleStatisticsUnit() throws Exception {
        communicator.setIncludePropertyGroups("PortGeneralInformation, PortConfigurationInformation, PortNeighborInformation, POEInformation, PortInboundStatistics, PortOutboundStatistics");
        communicator.setMonitoringMode("Unit");
        communicator.setManagementUnitSerialNumber("74W12C57F000F");
        List<Statistics> statisticsList = communicator.getMultipleStatistics();
        List<AggregatedDevice> units = communicator.retrieveMultipleStatistics();
        Assert.isTrue(((GenericStatistics)statisticsList.get(0)).getCpuPercentage() != null, "Device multiple statistics shouldn't be empty");
        Assert.isTrue(!((ExtendedStatistics)statisticsList.get(1)).getStatistics().isEmpty(), "Device multiple statistics should not be empty");
        Assert.isTrue(units.isEmpty(), "Aggregated devices list should be empty");
    }

    /**
     * If no errors are produced - we're golden.
     * The operation is fire-and-forget type, so we consider the operation to succeed, unless we don't have
     * exceptions other than {@link ResourceNotReachableException}
     * */
    @Test
    public void testDeviceReboot() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("");
        controllableProperty.setProperty("Reboot");
        controllableProperty.setValue("Reboot");

        communicator.controlProperty(controllableProperty);
    }

    /**
     * off = 1
     * quiet = 2
     * cool = 3
     * */
    @Test
    public void testDeviceFanStatusUpdate() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("");
        controllableProperty.setProperty("FanMode");
        controllableProperty.setValue("2");

        communicator.controlProperty(controllableProperty);
    }
    @Test
    public void testUnitDevicePOEAvailabilityUpdate() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("74W12C57F000F");
        controllableProperty.setProperty("Port00_01_POE#POEDetectionType");
        controllableProperty.setValue("2");

        communicator.controlProperty(controllableProperty);
    }
    @Test
    public void testUnitDevicePOEPowerLimitModeUpdate() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("");
        controllableProperty.setProperty("Port00_01_POE#POEEnable");
        controllableProperty.setValue("2");

        communicator.controlProperty(controllableProperty);
    }
    @Test
    public void testUnitDevicePOEPowerLimitUpdate() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("");
        controllableProperty.setProperty("Port00_01_POE#POEPowerLimitMode");
        controllableProperty.setValue("2");

        communicator.controlProperty(controllableProperty);
    }
    @Test
    public void testUnitDevicePOEDetectionTypeUpdate() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("");
        controllableProperty.setProperty("Port00_01_POE#POEPowerMode");
        controllableProperty.setValue("2");

        communicator.controlProperty(controllableProperty);
    }
    @Test
    public void testUnitDevicePOEPriorityUpdate() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("");
        controllableProperty.setProperty("Port00_01_POE#POEPowerLimit");
        controllableProperty.setValue("2");

        communicator.controlProperty(controllableProperty);
    }
    @Test
    public void testUnitDevicePOEPowerModeUpdate() throws Exception {
        ControllableProperty controllableProperty = new ControllableProperty();
        controllableProperty.setDeviceId("");
        controllableProperty.setProperty("Port00_01_POE#POEPriority");
        controllableProperty.setValue("2");

        communicator.controlProperty(controllableProperty);
    }
}
