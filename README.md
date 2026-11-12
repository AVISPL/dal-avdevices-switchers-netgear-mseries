# dal-avdevices-switchers-netgear-mseries

Netgear's Pro AV solutions are engineered specifically for AV over IP with out-of-the-box support for every 
networked AV solution Compatible with the following series of Netgear Managed Switches:
M4250, M4300, M4350, M4500

*Main adapter capabilities*
 - General stack unit device information
 - Stack unit details
 - Basic controls for AVUI API access point device (reboot, fan mode)
 - POE monitoring and control
 - Unit FAN status monitoring
 - Unit Sensor status monitoring
 - Port Neighbor information monitoring
 - Port data statistics

*Unit monitoring mode*
 - The monitored unit is the stack unit with the configured managementUnitSerialNumber, or unit 1 when it is not set.
 - If the monitored unit is not active (an inactive stack member is still listed by the switch as "Not Present"), 
   the device is shown in error with the message `Stack unit <serial> (unit <number>) is not active`. 
   The adapter does not switch to another unit.
