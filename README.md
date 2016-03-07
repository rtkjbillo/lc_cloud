# LIMA CHARLIE
<img src="https://raw.github.com/refractionPOINT/limacharlie/master/doc/lc.png" width="200">

*Stay up to date with new features and detection modules: [@rp_limacharlie](https://twitter.com/rp_limacharlie)*
*Need help? Contact other LC users via the Google Group: https://groups.google.com/d/forum/limacharlie*
*For more direct enquiries, contact us at limacharlie@refractionpoint.com*

## Documentation
Most of the documentation is now found on the [LC wiki](https://github.com/refractionPOINT/limacharlie/wiki).

[LimaCharlie Youtube channel](https://www.youtube.com/channel/UCR0GhNmc4gVcD9Uj07HS5AA) contains overview and tutorial videos.

## Overview
LIMA CHARLIE is an endpoint security platform. It is itself a collection of small projects all working together
to become the LC platform. LC gives you a cross-platform (Windows, OSX, Linux, Android and iOS) low-level 
environment allowing you to manage and push (in memory) additional modules to. The main module (at the moment) 
is the HBS sensor, which provides telemetry gathering and basic forensic capabilities.
 
Many of those individual features are provided through other platforms, so why LC? LC gives you a single 
messaging, cloud and analytic fabric that will integrate with anything and scale up. Sensor is extra-light
and installs nothing on the host.

Ultimately LC is meant to be a platform for the security community to experiment with, a starter kit to have the 
endpoint monitoring you want or to the platform enabling you to try new endpoint techniques without the hassle of
rebuilding the basics.)

## Next Steps
Please, feel at home contributing and testing out with the platform, it's what its for. HBS currently has some limitations
, mainly around being User Mode only. User Mode is great for stability (not going to blue screen boxes) and speed
of prototyping, but it lacks many of the low level event-driven APIs to do things like getting callbacks for processes
creation. So here are some of the capabilities that are coming:
- Kernel Mode thin module providing low level events and APIs.
- Make Linux and OS X capabilities on par with Windows.
- Keep on adding detections and modeling to enable better and faster hunting.

## Screen Shots
### Command Line Interface
![CLI](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_cli.png)

### Web UI Host List
![HostList](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_hostlist.png)

### Web UI Host View
![HostView](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_hostview.png)

### Web UI Object View
![ObjectView](https://raw.github.com/refractionPOINT/limacharlie/master/doc/screenshots/ss_object.png)
