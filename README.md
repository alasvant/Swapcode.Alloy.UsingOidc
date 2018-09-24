# Swapcode.Alloy.UsingOidc
Sample Episerver Alloy site using OpenID Connect to authenticate users.

This sample is configured to be used with [Swapcode.IdentityServer.ForDevs](https://github.com/alasvant/Swapcode.IdentityServer.ForDevs)

# Installing and testing

Copy, clone or download this reposiory and the [Swapcode.IdentityServer.ForDevs](https://github.com/alasvant/Swapcode.IdentityServer.ForDevs).

Before running this Episerver Alloy site you need to extract the database files from the EpiserverAssets.zip (under the [EpiserverAssets](EpiserverAssets) folder) and place them under the [App_Data](Swapcode.AlloyWeb/App_Data) folder.

This site uses Episerver Find so you should get your own developer/demo index from [Episerver Find site](https://find.episerver.com/) and then create a XML file called Find.localdev.config and place it to Swapcode.AlloyWeb project root.
```
<?xml version="1.0" encoding="utf-8"?> -->
<episerver.find serviceUrl="http://YOUR_URI/" defaultIndex="YOUR_INDEX" />
```

# Other stuff
Look at the [web.config](Swapcode.AlloyWeb/Web.config) and search for 'Edited:' string to see modifications to the file.

[Global.asax.cs](Swapcode.AlloyWeb/Global.asax.cs) has one modification to disable MVC version header.

Files added are in the [Business/Claims](Swapcode.AlloyWeb/Business/Claims) folder.

[Startup.cs](Swapcode.AlloyWeb/Startup.cs) contains the OIDC configuration code.
