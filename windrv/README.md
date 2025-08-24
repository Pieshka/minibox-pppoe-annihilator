# USB Serial Console driver

This  directory  contains  the  `minibox-port.inf`  driver,  which  can  be  installed  on  Microsoft  Windows  systems.

> **NOTE!** By default, Minibox PPPoE Annihilator contains USB VID and PID belonging to NetChip (VID: 0x0525, PID: 0xA4A7) made available for Linux Foundation purposes. If  you  want  to  distribute  a  device  with  Minibox  PPPoE  Annihilator  installed,  you  must  change  this  data  to  your  own.  Both  in  the  driver  and  in  the  `S50gadgets`  script  that  activates  the  USB  gadget.

### When  installation is necessary?

You must install this driver on your system if:
* You are connecting a device with Minibox PPPoE Annihilator installed to Microsoft Windows XP - 8.1 operating systems, as these may not install the generic driver by default.
*  You  want  the  device  to  appear  under  its  own  name  in  Device  Manager  (and  terminal  software).

### Signing  the  driver  with  a  digital  signature

Since  the  release  of  Microsoft  Windows  10  64-bit,  every  driver  must  be  signed  with  a  valid  EV  Code  Signing  certificate.  Additionally,  if  the  driver  contains  kernel-loaded  modules,  it  must  also  be  signed  by  Microsoft  Corporation.

The virtual COM port driver used by Minibox PPPoE Annihilator uses kernel modules prepared by Microsoft Corporation, so it is sufficient to sign the driver with any purchased EV Code Signing certificate.

There is also an option to sign the driver with a self-signed certificate. In this case, the certificate must be pre-installed on the user's operating system.

> I do not recommend installing self-signed certificates in the user's operating system. It is not worth the risk (because on systems where the driver needs to be installed, there is no enforcement of signing anyway).
