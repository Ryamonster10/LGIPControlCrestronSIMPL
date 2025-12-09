# LGIPControlCrestronSIMPL
SIMPL+ and SIMPL Sharp code for 3 or 4 series processors that allows IP control of any modern LG display that uses an encrypted connection.

## HOW TO USE:

### Install:
Simply take the complied CLZ SIMPL Sharp file provided, along with the complied and manually move them into the "Usrplus" folder. Close and open SIMPL Windows. You should see the module in your "User Modules" tab at the bottom of the logic section.

### Setup:
Add your TV as a generic TCP/IP client device (configure tab, Ethernet Control Modules, Ethernet Intersystem/Device communication, TCP/IP Client, drag that onto your processor's ethernet slot, right click it, press configure, enter the ip address of your display, and give it a name for the funsies)

### TV Setup:
Go to menu, all settings, hover over networking but dont click on it, and then quickly, press 82888 using the remote numeric buttons. You should see a more advanced networking menu pop up. Note the IP Address and, optionally the Mac Address if you wish to use this module to power on the display from sleep. Select and enable "Network IP Control", and optionally "Wake on LAN". Click generate key code. Note down the key code. It should be 8 charecters.

### Usage:
Drag this module into your program, connect the rx, tx, and connect signals between this module and your TCP/IP client device. If you don't care about the log set it to //. If you do but don't want the complier to yell at you call it something like "//_tv_log". As long as it starts with a // the complier won't complain about it not being used, but providing a name afterwards means it will still show up in the SIMPL Debugger in toolbox. From there, simply pulse the digitals you need to control your display, and I recomend turning off all the energy saving stuff as it doesn't work great with IP control.

### Happy Crestron-ing!

## FAQ:
### Isnt there a Crestron module for this?
--> Yes there are two. The one that this repo directly replaces hasn't been updated in a few years, and won't run due to an out of date JSON dependacy, and the other one (offical Crestron driver) did not work for me.
### Why this over RS232C or IR?
--> Ive recently been doing a lot of installations with LG panels and Apple TVs. Using this, plus the ultamation module to control the Apple TV means you can litteraly plug both things in, connect them to WiFi and control them without any additional hardware (and any way to wirelessly get RS232 or IR from Crestron is upwards of $500 per unit last time I checked). But if you have the money, or are already installing a unit behind the TV that gets you RS232 or IR, that is probably the better option if you are getting it to work reliably.
### Is this free?
--> Yes it is completely free for non commerical, personal use, or commerical use for testing in their own space. (For example, if you a church and you are using this module in your own space to control TVs that you own, than you are free to use this for free (pun intented)). However if you are a commerical AV Dealer, and want to use this module for your clients, I kindly ask that you pay a very reasonable $500 one time charge (as outlined in the LICNESE file) for the ability to use this module on any job you have, prepetually (it will licnese your company). Feel free to test in your own space and try this module out. The source code is provided and if you make any changes that help you/your clients, PRs are more than welcome (for everyone!) and you'd be supporting open source software.
### I am a commerical AV Dealer, how do I pay?
--> Email me at ryan@thestonegroup.org, I will send you a Stripe Invoice. (please let me know if youre in New York State so I can add sales tax!)
### I have an issue.
--> Make an issue using GitHub issues, or go fix it and make a PR! Both are more than welcome.


### Thank you so much for stopping by, have a great rest of your day --Ryan.
