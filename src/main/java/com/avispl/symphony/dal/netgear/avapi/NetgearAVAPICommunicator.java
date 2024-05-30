/*
 * Copyright (c) 2024 AVI-SPL, Inc. All Rights Reserved.
 */
package com.avispl.symphony.dal.netgear.avapi;

import com.avispl.symphony.api.dal.control.Controller;
import com.avispl.symphony.api.dal.dto.control.AdvancedControllableProperty;
import com.avispl.symphony.api.dal.dto.control.ControllableProperty;
import com.avispl.symphony.api.dal.dto.monitor.ExtendedStatistics;
import com.avispl.symphony.api.dal.dto.monitor.GenericStatistics;
import com.avispl.symphony.api.dal.dto.monitor.Statistics;
import com.avispl.symphony.api.dal.dto.monitor.aggregator.AggregatedDevice;
import com.avispl.symphony.api.dal.error.ResourceNotReachableException;
import com.avispl.symphony.api.dal.monitor.Monitorable;
import com.avispl.symphony.api.dal.monitor.aggregator.Aggregator;
import com.avispl.symphony.dal.aggregator.parser.AggregatedDeviceProcessor;
import com.avispl.symphony.dal.aggregator.parser.PropertiesMapping;
import com.avispl.symphony.dal.aggregator.parser.PropertiesMappingParser;
import com.avispl.symphony.dal.communicator.RestCommunicator;
import com.avispl.symphony.dal.netgear.avapi.data.*;
import com.avispl.symphony.dal.netgear.avapi.http.OctetStreamToJsonConverter;
import com.avispl.symphony.dal.netgear.avapi.utils.Utils;
import com.avispl.symphony.dal.util.StringUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.login.FailedLoginException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.avispl.symphony.dal.util.ControllablePropertyFactory.*;
import static java.util.concurrent.CompletableFuture.runAsync;

/**
 * Netgear AVUI API Communicator
 * Current list of features includes:
 * - General stack unit device information
 * - Stack unit details
 * - Basic controls for AVUI API access point device (reboot, fan mode)
 * - POE monitoring and control
 * - Unit FAN status monitoring
 * - Unit Sensor status monitoring
 * - Port Neighbor information monitoring
 * - Port data statistics
 *
 * @author Maksym.Rossiitsev/AVISPL Team
 */
public class NetgearAVAPICommunicator extends RestCommunicator implements Monitorable, Controller, Aggregator {
    /**
     * Request interceptor is needed to seamlessly refresh {@link NetgearAVAPICommunicator#authorizationToken}
     * */
    class NetgearRequestInterceptor implements ClientHttpRequestInterceptor {
        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            ClientHttpResponse response = null;
            try {
                response = execution.execute(request, body);
                if (response.getRawStatusCode() == 403 && !request.getURI().toString().contains(Constants.URI.LOGIN)) {
                    authorizationToken = null;
                    authenticate();
                    return execution.execute(request, body);
                }
            } catch (Exception e) {
                logger.error("Error occured during request interception", e);
            }
            return response;
        }
    }

    private NetgearRequestInterceptor netgearRequestInterceptor;
    /**
     * Adapter metadata properties (build date, version)
     * */
    private Properties adapterProperties;

    /**
     * Device properties processor for json data extraction, using yml mapping
     * */
    private AggregatedDeviceProcessor deviceDataProcessor;

    /**
     * Octet to json converter, to cover the scenarios in which Netgear AVUI API does not provide Content-Type headers
     * */
    private OctetStreamToJsonConverter octetStreamToJsonConverter;

    /**
     * Device adapter instantiation timestamp.
     */
    private long adapterInitializationTimestamp;

    /**
     * Cached serialNumber:unitId map for unit matching and searching purposes
     */
    private BiMap<String, String> serialNumberToUnitNumber = HashBiMap.create();

    /**
     * Cached aggregated stack units
     * */
    private Map<String, AggregatedDevice> aggregatedStackUnits = new ConcurrentHashMap<>();

    /**
     * Include property groups, current values are:
     * PortGeneralInformation, PortConfigurationInformation, PortNeighborInformation, POEInformation, PortInboundStatistics, PortOutboundStatistics
     * */
    private final List<String> includePropertyGroups = new ArrayList<>(); // Basic by default, 'All' for all, PortGeneralInformation, PortConfigurationInformation, PortNeighborInformation

    /**
     * Management (API) unit serial number, to properly set aggregator metadata and unit device details
     * */
    private String managementUnitSerialNumber;

    /**
     * Adapter mode - stack or single unit device monitoring
     * */
    private MonitoringMode monitoringMode = MonitoringMode.STACK;

    /**
     * Ping mode - ICMP or TCP, depending on network configuration
     * */
    private PingMode pingMode = PingMode.ICMP;

    private String authorizationToken;

    /**
     * This method returns the device Ping mode
     * @return String This returns the current ping mode.
     */
    public String getPingMode() {
        return pingMode.name();
    }

    /**
     * This method is used set the device ping mode
     * @param pingMode This is the ping mode to set
     */
    public void setPingMode(String pingMode) {
        this.pingMode = PingMode.ofString(pingMode);
    }

    /**
     * This method returns the device Monitoring mode
     * @return String This returns the current monitoring mode.
     */
    public String getMonitoringMode() {
        return monitoringMode.name();
    }

    /**
     * This method is used set the device monitoring mode
     * @param monitoringMode This is the monitoring mode to set
     */
    public void setMonitoringMode(String monitoringMode) {
        this.monitoringMode = MonitoringMode.ofString(monitoringMode);
    }

    /**
     * This method returns the device property groups
     * @return String This returns the current property groups.
     */
    public String getIncludePropertyGroups() {
        return String.join(",", includePropertyGroups);
    }

    /**
     * This method returns the management device's serial number
     * @return String This returns the current management device serial number.
     */
    public String getManagementUnitSerialNumber() {
        return managementUnitSerialNumber;
    }

    /**
     * This method is used set the management unit device serial number
     * @param managementUnitSerialNumber This is the serial number port to set
     */
    public void setManagementUnitSerialNumber(String managementUnitSerialNumber) {
        this.managementUnitSerialNumber = managementUnitSerialNumber;
    }

    /**
     * This method is used set the adapter's include property groups values
     * @param includePropertyGroups This is the include property groups values to set
     */
    public void setIncludePropertyGroups(String includePropertyGroups) {
        this.includePropertyGroups.clear();
        Arrays.stream(includePropertyGroups.split(",")).forEach(propertyName -> this.includePropertyGroups.add(propertyName.trim()));
    }

    public NetgearAVAPICommunicator() throws IOException {
        super();
        setTrustAllCertificates(true);
        setBaseUri(Constants.URI.BASE_URI);
        adapterProperties = new Properties();
        adapterProperties.load(getClass().getResourceAsStream("/version.properties"));
        netgearRequestInterceptor = new NetgearRequestInterceptor();
    }

    @Override
    protected void internalInit() throws Exception {
        adapterInitializationTimestamp = System.currentTimeMillis();
        Map<String, PropertiesMapping> mapping = new PropertiesMappingParser().loadYML("mapping/model-mapping.yml", getClass());
        deviceDataProcessor = new AggregatedDeviceProcessor(mapping);
        octetStreamToJsonConverter = new OctetStreamToJsonConverter(deviceDataProcessor);
        super.internalInit();
    }

    @Override
    protected void internalDestroy() {
        aggregatedStackUnits.clear();
        serialNumberToUnitNumber.clear();

        super.internalDestroy();
    }

    @Override
    public void controlProperty(ControllableProperty controllableProperty) throws Exception {
        String property = controllableProperty.getProperty();
        String propertyValue = controllableProperty.getValue().toString();
        String deviceId = controllableProperty.getDeviceId();

        if (property.endsWith(Constants.Properties.REBOOT)) {
            rebootDevice();
            return;
        }
        if (property.endsWith(Constants.Properties.FAN_MODE)) {
            updateFanMode(propertyValue);
            return;
        }

        if (property.contains("POE")) {
            if (logger.isDebugEnabled()) {
                logger.debug("Attempt to apply POE configuration for property " + property);
            }
            if (!property.contains(Constants.Misc.HASH)) {
                throw new UnsupportedOperationException(String.format("Property control for property %s is unsupported", property));
            }

            String ungroupedProperty = property.split(Constants.Misc.HASH)[1];
            String devicePropertyName = Constants.PROPERTY_NAME_TO_DEVICE_PROPERTY_NAMES.get(ungroupedProperty);
            if (StringUtils.isNullOrEmpty(devicePropertyName)) {
                throw new UnsupportedOperationException(String.format("Property control for property %s is unsupported", property));
            }
            String unitId = serialNumberToUnitNumber.get(deviceId);
            if (StringUtils.isNullOrEmpty(unitId)) {
                throw new IllegalArgumentException("Unable to process control operation: cannot find unit id for device with id " + deviceId);
            }
            String portId = extractPortNumberFromPropertyName(property);
            if (StringUtils.isNullOrEmpty(portId)) {
                throw new IllegalArgumentException("Unable to process control operation: cannot identify port for property " + property);
            }
            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Applying POE configuration for port %s on unit %s, with property name %s and value %s", portId, unitId, devicePropertyName, propertyValue));
            }
            updatePoEConfig(unitId, portId, devicePropertyName, propertyValue);
        }
    }

    @Override
    public void controlProperties(List<ControllableProperty> list) throws Exception {
        if (CollectionUtils.isEmpty(list)) {
            throw new IllegalArgumentException("Controllable properties cannot be null or empty");
        }
        for (ControllableProperty controllableProperty : list) {
            controlProperty(controllableProperty);
        }
    }

    @Override
    public List<Statistics> getMultipleStatistics() throws Exception {
        ExtendedStatistics extendedStatistics = new ExtendedStatistics();
        Map<String, String> statistics = new HashMap<>();
        extendedStatistics.setStatistics(statistics);

        if (monitoringMode == MonitoringMode.STACK) {
            return Arrays.asList(extendedStatistics);
        }
        if (StringUtils.isNullOrEmpty(managementUnitSerialNumber)) {
            statistics.put("Error", "Management unit serial number is not configured.");
            return Arrays.asList(extendedStatistics);
        }
        generateAdapterMetadata(statistics);
        processDeviceInformation();
        processPortInformation();
        processPortConfigurationInformation();
        processPortNeighborInformation();
        processPOEInformation();
        processPortInboundStatisticsInformation();
        processPortOutboundStatisticsInformation();
        statistics.putAll(aggregatedStackUnits.get(managementUnitSerialNumber).getProperties());

        return Collections.singletonList(extendedStatistics);
    }

    @Override
    public List<AggregatedDevice> retrieveMultipleStatistics() throws Exception {
        if (monitoringMode == MonitoringMode.STACK) {
            processDeviceInformation();
            processPortInformation();
            processPortConfigurationInformation();
            processPortNeighborInformation();
            processPOEInformation();
            processPortInboundStatisticsInformation();
            processPortOutboundStatisticsInformation();
            return new ArrayList<>(aggregatedStackUnits.values());
        } else if (monitoringMode == MonitoringMode.UNIT){
            return new ArrayList<>();
        }
        throw new IllegalArgumentException("Illegal monitoring mode: " + monitoringMode);
    }

    @Override
    public List<AggregatedDevice> retrieveMultipleStatistics(List<String> list) throws Exception {
        return retrieveMultipleStatistics()
                .stream()
                .filter(aggregatedDevice -> list.contains(aggregatedDevice.getDeviceId()))
                .collect(Collectors.toList());
    }

    @Override
    protected void authenticate() throws Exception {
        processLoginRequest();
    }

    @Override
    protected HttpHeaders putExtraRequestHeaders(HttpMethod httpMethod, String uri, HttpHeaders headers) throws Exception {
        if (!headers.containsKey("Content-Type")) {
            headers.add("Content-Type", "application/json");
        }
        if (!headers.containsKey("Accept")) {
            headers.add("Accept", "application/json");
        }
        if (!uri.contains(Constants.URI.LOGIN)) {
            if (StringUtils.isNullOrEmpty(authorizationToken)) {
                processLoginRequest();
            }
            headers.remove("Session");
            headers.add("Session", authorizationToken);
        }
        return super.putExtraRequestHeaders(httpMethod, uri, headers);
    }

    /**
     * {@inheritDoc}
     *
     * We need to make sure {@link OctetStreamToJsonConverter} is in the converters list, as
     * netgear AVUI provides no Content-Type in response headers.
     *
     * On top of that, we need to use {@link NetgearRequestInterceptor} to manage access token invalidation
     * */
    @Override
    protected RestTemplate obtainRestTemplate() throws Exception {
        RestTemplate restTemplate = super.obtainRestTemplate();
        List<HttpMessageConverter<?>> converters = restTemplate.getMessageConverters();
        if (converters.stream().noneMatch(httpMessageConverter -> httpMessageConverter instanceof OctetStreamToJsonConverter)) {
            converters.add(octetStreamToJsonConverter);
        }
        List<ClientHttpRequestInterceptor> interceptors = restTemplate.getInterceptors();
        if (!interceptors.contains(netgearRequestInterceptor))
            interceptors.add(netgearRequestInterceptor);
        return restTemplate;
    }


    @Override
    public int ping() throws Exception {
        if (pingMode == PingMode.ICMP) {
            return super.ping();
        } else if (pingMode == PingMode.TCP) {
            if (isInitialized()) {
                long pingResultTotal = 0L;

                for (int i = 0; i < this.getPingAttempts(); i++) {
                    long startTime = System.currentTimeMillis();

                    try (Socket puSocketConnection = new Socket(this.host, this.getPort())) {
                        puSocketConnection.setSoTimeout(this.getPingTimeout());
                        if (puSocketConnection.isConnected()) {
                            long pingResult = System.currentTimeMillis() - startTime;
                            pingResultTotal += pingResult;
                            if (this.logger.isTraceEnabled()) {
                                this.logger.trace(String.format("PING OK: Attempt #%s to connect to %s on port %s succeeded in %s ms", i + 1, host, this.getPort(), pingResult));
                            }
                        } else {
                            if (this.logger.isDebugEnabled()) {
                                logger.debug(String.format("PING DISCONNECTED: Connection to %s did not succeed within the timeout period of %sms", host, this.getPingTimeout()));
                            }
                            return this.getPingTimeout();
                        }
                    } catch (SocketTimeoutException | ConnectException tex) {
                        throw new SocketTimeoutException("Socket connection timed out");
                    } catch (UnknownHostException tex) {
                        throw new SocketTimeoutException("Socket connection timed out" + tex.getMessage());
                    } catch (Exception e) {
                        if (this.logger.isWarnEnabled()) {
                            this.logger.warn(String.format("PING TIMEOUT: Connection to %s did not succeed, UNKNOWN ERROR %s: ", host, e.getMessage()));
                        }
                        return this.getPingTimeout();
                    }
                }
                return Math.max(1, Math.toIntExact(pingResultTotal / this.getPingAttempts()));
            } else {
                throw new IllegalStateException("Cannot use device class without calling init() first");
            }
        } else {
            throw new IllegalArgumentException("Unknown PING Mode: " + pingMode);
        }
    }

    /**
     * Process AVUI API Login Request using username and password provided
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processLoginRequest() throws Exception {
        authorizationToken = "";
        Map<String, Map<String, String>> requestWrapper = new HashMap<>();
        Map<String, String> requestParameters = new HashMap<>();
        requestParameters.put(Constants.JsonProperties.NAME, getLogin());
        requestParameters.put(Constants.JsonProperties.PASSWORD, getPassword());
        requestWrapper.put(Constants.JsonProperties.USER, requestParameters);
        try {
            JsonNode response = doPost(Constants.URI.LOGIN, requestWrapper, JsonNode.class);
            authorizationToken = response.at(Constants.JsonPaths.USER_SESSION).asText();

            //Basic response validation is done in OctetStreamToJsonConverter to avoid double-converting response
            if (StringUtils.isNullOrEmpty(authorizationToken)) {
                throw new FailedLoginException("Login failed: empty authorization token, please check device credentials.");
            }
        } catch (Exception e) {
            throw new FailedLoginException("Login failed: " + e.getMessage());
        }
    }

    /**
     * Generate adapter metadata and add it to device's statistics
     *
     * @param statistics map of properties to add data to
     * */
    private void generateAdapterMetadata(Map<String, String> statistics) {
        statistics.put(Constants.Properties.ADAPTER_VERSION, adapterProperties.getProperty("adapter.version"));
        statistics.put(Constants.Properties.ADAPTER_BUILD_DATE, adapterProperties.getProperty("adapter.build.date"));
        statistics.put(Constants.Properties.ADAPTER_UPTIME, normalizeUptime((System.currentTimeMillis() - adapterInitializationTimestamp) / 1000));
    }

    /**
     * Retrieve and process stack unit information
     * Device details json is passed here so all we need is to extract device details and add it to the
     * corresponding unit device statistics (unitId:unitSerialNumber match)
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processDeviceInformation() throws Exception {
        JsonNode deviceInfoResponse = doGet(Constants.URI.DEVICE_INFO, JsonNode.class);
        Map<String, String> stackInfo = new HashMap<>();

        processDeviceDetailsInformation(deviceInfoResponse.withArray(Constants.JsonPaths.DEVICE_INFO_DETAILS));
        processDeviceFanInformation(deviceInfoResponse.withArray(Constants.JsonPaths.DEVICE_INFO_FAN));
        processDeviceSensorInformation(deviceInfoResponse.withArray(Constants.JsonPaths.DEVICE_INFO_SENSOR));
        processDeviceCPUInformation(deviceInfoResponse.withArray(Constants.JsonPaths.DEVICE_INFO_CPU));
        processDeviceMemoryInformation(deviceInfoResponse.withArray(Constants.JsonPaths.DEVICE_INFO_MEMORY));

        if (StringUtils.isNotNullOrEmpty(managementUnitSerialNumber)) {
            AggregatedDevice unitDevice = aggregatedStackUnits.get(managementUnitSerialNumber);
            if (unitDevice == null) {
                if (logger.isWarnEnabled()) {
                    logger.warn("");
                }
                return;
            }
            Map<String, String> unitProperties = unitDevice.getProperties();
            List<AdvancedControllableProperty> unitControls = unitDevice.getControllableProperties();
            if (unitControls == null) {
                unitControls = new ArrayList<>();
                unitDevice.setControllableProperties(unitControls);
            }
            unitControls.add(createButton(Constants.Properties.REBOOT, Constants.Properties.REBOOT, "Rebooting...", 60000L));
            unitProperties.put(Constants.Properties.REBOOT, Constants.Properties.REBOOT);

            generateAdapterMetadata(unitProperties);
            deviceDataProcessor.applyProperties(stackInfo, deviceInfoResponse, Constants.Properties.DEVICE_INFO);
            for(Map.Entry<String, String> entry: stackInfo.entrySet()){
                String key = entry.getKey();
                String value = entry.getValue();

                String propertyName = Constants.Properties.DEVICE_INFO + Constants.Misc.HASH + key;
                if (Constants.Properties.FAN_MODE.equals(key)) {
                    AdvancedControllableProperty fanModeToggle = createPreset(propertyName, new ArrayList<>(Constants.FAN_MODE_VALUES.keySet()), new ArrayList<>(Constants.FAN_MODE_VALUES.values()), value);
                    unitControls.add(fanModeToggle);
                }
                unitProperties.put(propertyName, value);
            }
        }
    }

    /**
     * Retrieve and process device details
     * The details are only populated for the unit which runs API currently, so we need to match it based on
     * the serial number provided.
     * @param deviceDetails json response that contains all device details of a given unit
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processDeviceDetailsInformation (ArrayNode deviceDetails) {
        for(JsonNode node: deviceDetails) {
            AggregatedDevice aggregatedUnitDevice = new AggregatedDevice();
            GenericStatistics aggregatedUnitGenericStatistics = new GenericStatistics();
            aggregatedUnitDevice.setMonitoredStatistics(Arrays.asList(aggregatedUnitGenericStatistics));

            Map<String, String> deviceDetailsUnit = new HashMap<>();

            deviceDataProcessor.applyProperties(deviceDetailsUnit, node, Constants.MapperModels.DEVICE_DETAILS_UNIT_INFO);
            String unitId = deviceDetailsUnit.get(Constants.Properties.UNIT_NUMBER);
            String serialNumber = deviceDetailsUnit.get(Constants.Properties.SERIAL_NUMBER);
            String deviceModel = deviceDetailsUnit.get(Constants.Properties.MODEL);
            String deviceActive = deviceDetailsUnit.get(Constants.Properties.ACTIVE);
            String deviceUptime = deviceDetailsUnit.get(Constants.Properties.UPTIME_RAW);
            serialNumberToUnitNumber.put(serialNumber, unitId);

            aggregatedUnitDevice.setDeviceId(serialNumber);
            aggregatedUnitDevice.setDeviceModel(deviceModel);
            aggregatedUnitDevice.setSerialNumber(serialNumber);
            aggregatedUnitDevice.setDeviceOnline(Boolean.parseBoolean(deviceActive));
            aggregatedUnitDevice.setCategory(Constants.Properties.SWITCHERS);
            aggregatedUnitDevice.setType(Constants.Properties.AV_DEVICES);
            aggregatedUnitDevice.setDeviceName(String.format("%s %s", deviceModel, serialNumber));

            Map<String, String> unitProperties = new HashMap<>();
            unitProperties.put(Constants.Properties.UNIT_NUMBER, unitId);
            unitProperties.put(Constants.Properties.MANAGEMENT, deviceDetailsUnit.get(Constants.Properties.MANAGEMENT));
            unitProperties.put(Constants.Properties.ACTIVE, deviceActive);
            unitProperties.put(Constants.Properties.FW_VERSION, deviceDetailsUnit.get(Constants.Properties.FW_VERSION));
            unitProperties.put(Constants.Properties.BOOT_VERSION, deviceDetailsUnit.get(Constants.Properties.BOOT_VERSION));
            unitProperties.put(Constants.Properties.UPTIME, String.format("%.0f", Math.floor((double)formatUptimeToLong(deviceUptime)/1000/3600)));

            aggregatedUnitDevice.setProperties(unitProperties);

            aggregatedUnitGenericStatistics.setUpTime(formatUptimeToLong(deviceUptime));
            aggregatedStackUnits.put(serialNumber, aggregatedUnitDevice);
        }
    }

    /**
     * Retrieve and process unit fan information
     * Fan details json is passed here so all we need is to extract fan usage and add it to the
     * corresponding unit device statistics (unitId:unitSerialNumber match)
     * @param fanDetails json response that contains all fan details of a given unit
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processDeviceFanInformation (ArrayNode fanDetails) {
        for(JsonNode fanNode: fanDetails) {
            String unitId = fanNode.at(Constants.JsonPaths.UNIT).asText();
            String cachedUnitSerialNumber = serialNumberToUnitNumber.inverse().get(unitId);
            AggregatedDevice cachedUnit = aggregatedStackUnits.get(cachedUnitSerialNumber);
            Map<String, String> cachedUnitProperties = cachedUnit.getProperties();

            ArrayNode fanNodeDetails = fanNode.withArray(Constants.JsonPaths.DETAILS);
            for(JsonNode details: fanNodeDetails) {
                Map<String, String> deviceDetailsFanUnit = new HashMap<>();
                deviceDataProcessor.applyProperties(deviceDetailsFanUnit, details, Constants.MapperModels.DEVICE_UNIT_FAN_INFO);
                String fanDescription = deviceDetailsFanUnit.get(Constants.Properties.DESCRIPTION);
                String propertyPrefix = String.format(Constants.Properties.FAN_N_GROUP, fanDescription);

                deviceDetailsFanUnit.forEach((key, value) -> {
                    if (Constants.Properties.STATE.equals(key)){
                        value = Constants.FAN_STATE_VALUES.get(value);
                    }
                    cachedUnitProperties.put(propertyPrefix + key, value);
                });
            }
        }
    }

    /**
     * Retrieve and process unit sensor information
     * Sensor details json is passed here so all we need is to extract sensor usage and add it to the
     * corresponding unit device statistics (unitId:unitSerialNumber match)
     * @param sensorDetails json response that contains all sensor details of a given unit
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processDeviceSensorInformation (ArrayNode sensorDetails) {
        for(JsonNode sensorNode: sensorDetails) {
            String unitId = sensorNode.at(Constants.JsonPaths.UNIT).asText();
            String cachedUnitSerialNumber = serialNumberToUnitNumber.inverse().get(unitId);
            AggregatedDevice cachedUnit = aggregatedStackUnits.get(cachedUnitSerialNumber);
            Map<String, String> cachedUnitProperties = cachedUnit.getProperties();

            ArrayNode sensorNodeDetails = sensorNode.withArray(Constants.JsonPaths.DETAILS);
            for(JsonNode details: sensorNodeDetails) {
                Map<String, String> deviceDetailsSensorUnit = new HashMap<>();
                deviceDataProcessor.applyProperties(deviceDetailsSensorUnit, details, Constants.MapperModels.DEVICE_UNIT_SENSOR_INFO);
                String fanID = deviceDetailsSensorUnit.get(Constants.Properties.DESCRIPTION);
                String propertyPrefix = String.format(Constants.Properties.SENSOR_N_GROUP, fanID);

                deviceDetailsSensorUnit.forEach((key, value) -> {
                    if (Constants.Properties.STATE.equals(key)){
                        value = Constants.SENSOR_STATE_VALUES.get(value);
                    }
                    cachedUnitProperties.put(propertyPrefix + key, value);
                });
            }
        }
    }

    /**
     * Retrieve and process unit CPU information
     * Sensor details json is passed here so all we need is to extract CPU usage and add it to the
     * corresponding unit device statistics (unitId:unitSerialNumber match)
     * @param cpuDetails json response that contains all CPU usage details of a given unit
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processDeviceCPUInformation (ArrayNode cpuDetails) {
        for (JsonNode cpuNode: cpuDetails) {
            String unitId = cpuNode.at(Constants.JsonPaths.UNIT).asText();
            String cachedUnitSerialNumber = serialNumberToUnitNumber.inverse().get(unitId);
            AggregatedDevice cachedUnit = aggregatedStackUnits.get(cachedUnitSerialNumber);

            List<Statistics> cachedUnitStatistics = cachedUnit.getMonitoredStatistics();
            if (cachedUnitStatistics == null) {
                cachedUnitStatistics = new ArrayList<>();
            }

            Statistics statistics = cachedUnitStatistics.stream().filter(stats -> stats instanceof GenericStatistics).findAny().orElse(null);
            if (statistics == null) {
                statistics = new GenericStatistics();
                cachedUnit.getMonitoredStatistics().add(statistics);
            }
            Float cpuUsage = Float.valueOf(cpuNode.at(Constants.JsonPaths.USAGE).asText().replace(Constants.Misc.PCT, ""));
            ((GenericStatistics)statistics).setCpuPercentage(cpuUsage);
        }
    }

    /**
     * Retrieve and process unit memory information
     * Memory details json is passed here so all we need is to extract memory usage and add it to the
     * corresponding unit device statistics (unitId:unitSerialNumber match)
     * @param memoryDetails json response that contains all memory details of a given unit
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processDeviceMemoryInformation (ArrayNode memoryDetails) {
        for (JsonNode memoryNode: memoryDetails) {
            String unitId = memoryNode.at(Constants.JsonPaths.UNIT).asText();
            String cachedUnitSerialNumber = serialNumberToUnitNumber.inverse().get(unitId);
            AggregatedDevice cachedUnit = aggregatedStackUnits.get(cachedUnitSerialNumber);
            Map<String, String> cachedUnitProperties = cachedUnit.getProperties();
            cachedUnitProperties.put(Constants.Properties.MEMORY_USAGE, memoryNode.at(Constants.JsonPaths.USAGE).asText().replace(Constants.Misc.PCT, ""));
        }
    }

    /**
     * Retrieve and process port information for all units
     * Since /swcfg_ports_status shares all units statistics, we don't need to specify any particular unit here.
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processPortInformation() throws Exception {
        if (!includePropertyGroups.contains(Constants.PropertyGroupEntries.PORT_GENERAL_INFORMATION)) {
            return;
        }
        JsonNode portStatus = doGet(Constants.URI.PORTS_STATUS, JsonNode.class); // Port data, gotta exclude lag (portStr contains lag)
        ArrayNode portsData = portStatus.withArray(Constants.JsonPaths.SWITCH_PORT_STATUS_ROWS);
        for (JsonNode port: portsData) {
            String portSrt = port.at(Constants.JsonPaths.PORT_STRING).asText();
            if (portSrt.contains(Constants.JsonProperties.LAG)) {
                // Exclude LAG for now
                continue;
            }
            Map<String, String> portData = new HashMap<>();
            deviceDataProcessor.applyProperties(portData, port, Constants.MapperModels.UNIT_PORT_INFO);

            String unitNo = port.at(Constants.JsonPaths.UNIT).asText();
            String unitSerialNumber = serialNumberToUnitNumber.inverse().get(unitNo);
            AggregatedDevice unitDevice = aggregatedStackUnits.get(unitSerialNumber);
            Map<String, String> cachedUnitProperties = unitDevice.getProperties();

            portData.forEach((key, value) -> {
                if (key.equals(Constants.Properties.ADMIN_STATE)) {
                    value = Constants.ADMIN_STATE_VALUES.get(value);
                }
                if (key.equals(Constants.Properties.LINK_STATE)) {
                    value = Constants.LINK_STATE_VALUES.get(value);
                }
                String portGroupName = String.format(Constants.Properties.PORT_N_GENERAL_INFORMATION_GROUP, formatPortName(portData.get(Constants.Properties.PORT_STRING)));
                cachedUnitProperties.put(portGroupName + key, value);
            });
        }

    }

    /**
     * Retrieve and process POE information of unit ports
     * Since /poe_config shares all units poe details, we don't need to specify any particular unit here.
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processPOEInformation() throws Exception {
        if (!includePropertyGroups.contains(Constants.PropertyGroupEntries.POE_INFORMATION)) {
            return;
        }
        JsonNode poePortsCfg = doGet(Constants.URI.POE_PORTS_CFG, JsonNode.class);

        ArrayNode poeNodes = poePortsCfg.withArray(Constants.JsonPaths.POE_PORT_CONFIG);
        for (JsonNode poeNode: poeNodes) {
            Map<String, String> poeProperties = new HashMap<>();
            deviceDataProcessor.applyProperties(poeProperties, poeNode, Constants.MapperModels.PORT_POE_INFORMATION);
            String unitNumber = poeProperties.get(Constants.Properties.UNIT_NUMBER);
            String portNumber = poeProperties.get(Constants.Properties.PORT_NUMBER);

            String unitSerialNumber = serialNumberToUnitNumber.inverse().get(unitNumber);
            if (StringUtils.isNullOrEmpty(unitSerialNumber)) {
                logger.warn("Unable to find serial number for unit with id " + unitNumber);
                continue;
            }
            AggregatedDevice unitDevice = aggregatedStackUnits.get(unitSerialNumber);
            Map<String, String> unitProperties = unitDevice.getProperties();
            List<AdvancedControllableProperty> controllableProperties = unitDevice.getControllableProperties();
            if (controllableProperties == null) {
                controllableProperties = new ArrayList<>();
                unitDevice.setControllableProperties(controllableProperties);
            }
            unitDevice.setControllableProperties(controllableProperties);
            String groupPrefix = String.format(Constants.Properties.PORT_N_POE_GROUP, Integer.parseInt(portNumber));
            for(Map.Entry<String, String> entry: poeProperties.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                String propertyName = groupPrefix + key;
                switch (key) {
                    case Constants.Properties.ENABLE:
                        AdvancedControllableProperty poeEnable = createSwitch(propertyName, Constants.Misc.TRUE.equals(value) ? 1 : 0);
                        controllableProperties.add(poeEnable);
                    break;
                    case Constants.Properties.POWER_LIMIT_MODE:
                        AdvancedControllableProperty powerLimitMode = createDropdown(propertyName, new ArrayList<>(Constants.POE_POWER_LIMIT_MODE_VALUES.keySet()), new ArrayList<>(Constants.POE_POWER_LIMIT_MODE_VALUES.values()), value);
                        controllableProperties.add(powerLimitMode);
                    break;
                    case Constants.Properties.CLASSIFICATION:
                        value = Constants.POE_CLASSIFICATION_VALUES.get(value);
                    break;
                    case Constants.Properties.POWER_LIMIT:
                        AdvancedControllableProperty powerLimit = createSlider(propertyName, 3000f, 32000f, Float.valueOf(value));
                        controllableProperties.add(powerLimit);
                    break;
                    case Constants.Properties.DETECTION_TYPE:
                        AdvancedControllableProperty detectionType = createDropdown(propertyName, new ArrayList<>(Constants.POE_DETECTION_TYPE_VALUES.keySet()), new ArrayList<>(Constants.POE_DETECTION_TYPE_VALUES.values()), value);
                        controllableProperties.add(detectionType);
                    break;
                    case Constants.Properties.PRIORITY:
                        AdvancedControllableProperty priority = createDropdown(propertyName, new ArrayList<>(Constants.POE_PRIORITY_VALUES.keySet()), new ArrayList<>(Constants.POE_PRIORITY_VALUES.values()), value);
                        controllableProperties.add(priority);
                    break;
                    case Constants.Properties.POWER_MODE:
                        AdvancedControllableProperty powerMode = createDropdown(propertyName, new ArrayList<>(Constants.POE_POWER_MODE_VALUES.keySet()), new ArrayList<>(Constants.POE_POWER_MODE_VALUES.values()), value);
                        controllableProperties.add(powerMode);
                    break;
                    default:
                        if (logger.isTraceEnabled()) {
                            logger.trace("Passing port configuration property without mapping: " + key);
                        }
                    break;
                }
                unitProperties.put(groupPrefix + key, value);
            }
        }

    }

    /**
     * Retrieve and process configuration information of unit ports
     * Since /swcfg_port shares all units details, we don't need to specify any particular unit here.
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processPortConfigurationInformation() throws Exception {
        if (!includePropertyGroups.contains(Constants.PropertyGroupEntries.PORT_CONFIGURATION_INFORMATION)) {
            return;
        }
        JsonNode portsCfg = doGet(Constants.URI.PORTS_CFG, JsonNode.class);
        ArrayNode unitPortConfigs = portsCfg.withArray(Constants.JsonPaths.SWITCH_PORT_CONFIG_UNIT);
        for (JsonNode unitConfig: unitPortConfigs) {
            String unitId = unitConfig.at(Constants.JsonPaths.ID).asText();
            String unitSerialNumber = serialNumberToUnitNumber.inverse().get(unitId);
            AggregatedDevice unitDevice = aggregatedStackUnits.get(unitSerialNumber);
            Map<String, String> unitProperties = unitDevice.getProperties();
            ArrayNode ports = unitConfig.withArray(Constants.JsonPaths.SLOT_0_PORT);
            for (JsonNode port: ports) {
                Map<String, String> portData = new HashMap<>();
                deviceDataProcessor.applyProperties(portData, port, Constants.MapperModels.PORT_CONFIGURATION_INFORMATION);
                String portGroupName = String.format(Constants.Properties.PORT_N_GENERAL_INFORMATION_GROUP, formatPortName(portData.get(Constants.Properties.PORT_STRING)));

                portData.forEach((key, value) -> {
                    switch (key) {
                        case Constants.Properties.MODULE_TYPE:
                            value = Constants.MODULE_TYPE_VALUES.get(value);
                        break;
                        case Constants.Properties.PORT_MODE:
                            value = Constants.PORT_MODE_VALUES.get(value);
                        break;
                        case Constants.Properties.PORT_STATE:
                            value = Constants.PORT_STATE_VALUES.get(value);
                        break;
                        case Constants.Properties.STP_MODE:
                            value = Constants.STP_MODE_VALUES.get(value);
                        break;
                        case Constants.Properties.AUTO_TRUNK:
                            value = Constants.AUTO_TRUNK_VALUES.get(value);
                        break;
                        case Constants.Properties.IS_VALID:
                            value = Constants.POE_IS_VALID_VALUES.get(value);
                        break;
                        case Constants.Properties.ADMIN_STATE:
                            value = Constants.ADMIN_STATE_VALUES.get(value);
                        break;
                        case Constants.Properties.LINK_STATE:
                            value = Constants.LINK_STATE_VALUES.get(value);
                        break;
                        default:
                            if (logger.isTraceEnabled()) {
                                logger.trace("Passing port configuration property without mapping: " + key);
                            }
                        break;
                    }
                    unitProperties.put(portGroupName + key, value);
                });
            }
        }
    }

    /**
     * Retrieve and process Port neighbor statistics of unit ports
     * Since /neighbor shares all units statistics, we don't need to specify any particular unit here.
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processPortNeighborInformation() throws Exception {
        if (!includePropertyGroups.contains(Constants.PropertyGroupEntries.PORT_NEIGHBOR_INFORMATION)) {
            return;
        }
        JsonNode neighborStatus = doGet(Constants.URI.NEIGHBOR_STATUS, JsonNode.class);
        ArrayNode rows = neighborStatus.withArray(Constants.JsonPaths.LLDP_REMOTE_DEVICE_ROWS);

        Map<String, Integer> portNeighborsCounter = new HashMap<>();
        for(JsonNode row: rows) {
            Map<String, String> rowData = new HashMap<>();
            deviceDataProcessor.applyProperties(rowData, row, Constants.MapperModels.NEIGHBOR_INFORMATION);

            String portString = rowData.get(Constants.Properties.PORT_STRING);
            String portName = formatPortName(portString);

            Integer neighborCounter = 1;
            if (portNeighborsCounter.containsKey(portName)) {
                neighborCounter = portNeighborsCounter.get(portName);
            } else {
                portNeighborsCounter.put(portName, neighborCounter);
            }

            String unitId = rowData.get(Constants.Properties.UNIT_ID);
            String serialNumber = serialNumberToUnitNumber.inverse().get(unitId);
            if (StringUtils.isNullOrEmpty(serialNumber)) {
                continue;
            }
            AggregatedDevice unitDevice = aggregatedStackUnits.get(serialNumber);
            if (unitDevice == null) {
                continue;
            }
            Map<String, String> unitProperties = unitDevice.getProperties();
            String portNeighborPropertyPrefix = String.format(Constants.Properties.PORT_N_NEIGHBOR_INFORMATION_N_GROUP, portName, neighborCounter);
            rowData.forEach((key, value) -> unitProperties.put(portNeighborPropertyPrefix + key, value));
            portNeighborsCounter.put(portName, neighborCounter + 1);
        }
    }

    /**
     * Retrieve and process Inbound statistics of unit ports
     * Since /port_statistics shares all units statistics, we don't need to specify any particular unit here.
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processPortInboundStatisticsInformation() throws Exception {
        if (!includePropertyGroups.contains(Constants.PropertyGroupEntries.PORT_INBOUND_INFORMATION)) {
            return;
        }
        JsonNode portInResponse = doGet(Constants.URI.PORT_IN_STATISTICS, JsonNode.class);
        ArrayNode portsInResponse = portInResponse.withArray(Constants.JsonPaths.PORT_STATISTICS_ROWS);
        for (JsonNode row: portsInResponse) {
            Map<String, String> rowData = new HashMap<>();
            deviceDataProcessor.applyProperties(rowData, row, Constants.MapperModels.IN_PORT_STATISTICS);
            String unit = row.at(Constants.JsonPaths.UNIT).asText();
            String portNumber = row.at(Constants.JsonPaths.PORT_NAME).asText();
            String unitSerialNumber = serialNumberToUnitNumber.inverse().get(unit);
            AggregatedDevice unitDevice = aggregatedStackUnits.get(unitSerialNumber);
            if (unitDevice == null) {
                continue;
            }
            Map<String, String> unitProperties = unitDevice.getProperties();
            String formattedPortNumber = formatPortName(portNumber);
            rowData.forEach((key, value) -> {
                unitProperties.put(String.format(Constants.Properties.PORT_N_STATISTICS_N_GROUP, formattedPortNumber, key), value);
            });
        }
    }

    /**
     * Retrieve and process Outbound statistics of unit ports
     * Since /port_statistics shares all units statistics, we don't need to specify any particular unit here.
     *
     * @throws Exception if any communication exception occurs
     * */
    private void processPortOutboundStatisticsInformation() throws Exception {
        if (!includePropertyGroups.contains(Constants.PropertyGroupEntries.PORT_OUTBOUND_INFORMATION)) {
            return;
        }
        JsonNode portOutResponse = doGet(Constants.URI.PORT_OUT_STATISTICS, JsonNode.class);
        ArrayNode portsOutResponse = portOutResponse.withArray(Constants.JsonPaths.PORT_STATISTICS_ROWS);
        for (JsonNode row: portsOutResponse) {
            Map<String, String> rowData = new HashMap<>();
            deviceDataProcessor.applyProperties(rowData, row, Constants.MapperModels.OUT_PORT_STATISTICS);
            String unit = row.at(Constants.JsonPaths.UNIT).asText();
            String portNumber = row.at(Constants.JsonPaths.PORT_NAME).asText();
            String unitSerialNumber = serialNumberToUnitNumber.inverse().get(unit);
            AggregatedDevice unitDevice = aggregatedStackUnits.get(unitSerialNumber);
            if (unitDevice == null) {
                continue;
            }
            Map<String, String> unitProperties = unitDevice.getProperties();
            String formattedPortNumber = formatPortName(portNumber);
            rowData.forEach((key, value) -> {
                unitProperties.put(String.format(Constants.Properties.PORT_N_STATISTICS_N_GROUP, formattedPortNumber, key), value);
            });
        }
    }

    /**
     * We cant expect a response here, it's more of a "fire-and-forget" pattern,
     * so we just expect that the device is rebooted if we end up having "ResourceNotReachableException".
     * However, we can't afford waiting for 30 seconds within a synchronous operation because it will effectively
     * trigger a timeout error, so this should be fired off as an async one.
     * */
    private void rebootDevice() throws Exception {
        runAsync(() -> {
            Map<String, Map<String, Object>> requestWrapper = new HashMap<>();
            Map<String, Object> request = new HashMap<>();
            requestWrapper.put(Constants.JsonProperties.POWER, request);
            request.put(Constants.JsonProperties.TYPE, Constants.JsonProperties.REBOOT);
            request.put(Constants.JsonProperties.SAVE, true);
            try {
                doPost(Constants.URI.DEVICE_POWER, requestWrapper, JsonNode.class);
            } catch (ResourceNotReachableException rnre) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Device reboot request is completed");
                }
            } catch (Exception e) {
                logger.error("Error encountered during device reboot request", e);
            }
        });
    }

    /**
     * Update fan mode of a switch device
     *
     * @param fanMode value, values are string numeric, 0-3
     * @throws Exception if communication error occurs
     * */
    private void updateFanMode(String fanMode) throws Exception {
        Map<String, Integer> request = new HashMap<>();
        request.put(Constants.JsonProperties.FAN_MODE, Integer.parseInt(fanMode));
        doPost(Constants.URI.DEVICE_FAN, request, JsonNode.class);
    }

    /**
     * Update POE configuration of a device
     *
     * @param unitId number of unit for which configuration changes should be applied
     * @param portId port id that configuration should be updated for
     * @param propertyName name of the property to update
     * @param propertyValue value to update the POE property with
     *
     * @throws Exception if any communication error occurs
     * */
    private void updatePoEConfig(String unitId, String portId, String propertyName, String propertyValue) throws Exception {
        Map<String, List<Map<String, Object>>> request = new HashMap<>();
        List<Map<String, Object>> requestBodyWrapper = new ArrayList<>();
        Map<String, Object> requestBody = new HashMap<>();
        Object objectValue;
        if (propertyName.equals(Constants.JsonProperties.ENABLE)) {
            objectValue = "1".equals(propertyValue);
        } else {
            objectValue = Integer.parseInt(propertyValue);
        }
        requestBody.put(Constants.JsonProperties.UNIT, unitId);
        requestBody.put(Constants.JsonProperties.PORT_N, portId);
        requestBody.put(Constants.JsonProperties.PORT, portId);
        requestBody.put(propertyName, objectValue);
        requestBodyWrapper.add(requestBody);
        request.put(Constants.JsonProperties.POE_PORT_CONFIG, requestBodyWrapper);
        doPost(Constants.URI.POE_CFG, request, JsonNode.class);
    }
    /**
     * Initial format is: 2 days, 0 hrs, 16 mins, 15 secs
     * If the device was recently booted, sections go down to 0 but are still present, like so:
     * 0 days, 0 hrs, 0 mins, 15 secs
     *
     *
     * */
    private Long formatUptimeToLong(String uptime) {
        List<String> periods = Arrays.asList(uptime.split(",")); // 0 is days, 1 is hours, 2 is minutes, 3 is seconds

        Long uptimeValue = 0L;
        try {
            Long days = Utils.extractNumber(periods.get(0));
            Long hours = Utils.extractNumber(periods.get(1));
            Long minutes = Utils.extractNumber(periods.get(2));
            Long seconds = Utils.extractNumber(periods.get(3));
            uptimeValue = (days * 24L * 60 * 60 + hours * 60 * 60 + minutes * 60 + seconds) * 1000L;
        } catch (ArrayIndexOutOfBoundsException iob) {
            logger.error("Unable to process device uptime with a given value: " + uptime);
            return uptimeValue;
        }

        return uptimeValue;
    }

    /**
     * Format port name to match 00_00 format (slot_portNumber)
     *
     * @param portName name of the port in format 1/0/1
     * @return port name in format 00_00
     * */
    private String formatPortName(String portName) {
        String formattedPortName = portName;
        Pattern pattern = Pattern.compile(Constants.Misc.PORT_NUMBER_TEMPLATE_REGEX);
        Matcher matcher = pattern.matcher(portName);
        if (matcher.find()) {
            formattedPortName = String.format(Constants.Misc.PORT_NUMBER_TEMPLATE, Integer.parseInt(matcher.group(1)), Integer.parseInt(matcher.group(2)));
        }
        return formattedPortName;
    }

    /**
     * Format 00_01 where first part is slot and second is port number
     *
     * @param portName in a full port property group format
     * @return port number in 00/99 format
     * */
    private String extractPortNumberFromPropertyName(String portName) {
        Pattern pattern = Pattern.compile(Constants.Misc.PORT_NUMBER_TEMPLATE_EXTRACT_REGEX);
        Matcher matcher = pattern.matcher(portName);
        String portNameLeadingZeros = null;
        if (matcher.find()) {
            portNameLeadingZeros = matcher.group(2);
        }
        if (StringUtils.isNullOrEmpty(portNameLeadingZeros)) {
            throw new IllegalArgumentException("");
        }
        return String.format("%.0f", portNameLeadingZeros.split("_")[1]);
    }

    /**
     * Uptime is received in seconds, need to normalize it and make it human readable, like
     * 1 day(s) 5 hour(s) 12 minute(s) 55 minute(s)
     * Incoming parameter is may have a decimal point, so in order to safely process this - it's rounded first.
     * We don't need to add a segment of time if it's 0.
     *
     * @param uptimeSeconds value in seconds
     * @return string value of format 'x day(s) x hour(s) x minute(s) x minute(s)'
     */
    private String normalizeUptime(long uptimeSeconds) {
        StringBuilder normalizedUptime = new StringBuilder();

        long seconds = uptimeSeconds % 60;
        long minutes = uptimeSeconds % 3600 / 60;
        long hours = uptimeSeconds % 86400 / 3600;
        long days = uptimeSeconds / 86400;

        if (days > 0) {
            normalizedUptime.append(days).append(" day(s) ");
        }
        if (hours > 0) {
            normalizedUptime.append(hours).append(" hour(s) ");
        }
        if (minutes > 0) {
            normalizedUptime.append(minutes).append(" minute(s) ");
        }
        if (seconds > 0) {
            normalizedUptime.append(seconds).append(" second(s)");
        }
        return normalizedUptime.toString().trim();
    }

    /**
     * Create dropdown controllable property
     *
     * @param name of the controllable property
     * @param options actual value of the control
     * @param labels human readable control value
     * @param initialValue current value of a control
     * */
    private AdvancedControllableProperty createDropdown(String name, List<String> options, List<String> labels, String initialValue) {
        AdvancedControllableProperty.DropDown dropDown = new AdvancedControllableProperty.DropDown();
        dropDown.setOptions(options.toArray(new String[0]));
        dropDown.setLabels(labels.toArray(new String[0]));
        return new AdvancedControllableProperty(name, new Date(), dropDown, initialValue);
    }

    /**
     * Create preset controllable property
     *
     * @param name of the controllable property
     * @param options actual value of the control
     * @param labels human readable control value
     * @param initialValue current value of a control
     * */
    private AdvancedControllableProperty createPreset(String name, List<String> options, List<String> labels, String initialValue) {
        AdvancedControllableProperty.Preset preset = new AdvancedControllableProperty.Preset();
        preset.setOptions(options.toArray(new String[0]));
        preset.setLabels(labels.toArray(new String[0]));
        return new AdvancedControllableProperty(name, new Date(), preset, initialValue);
    }
}
