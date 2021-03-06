package com.ing.wbaa.gargoyle.proxy

import akka.actor.ActorSystem
import com.ing.wbaa.gargoyle.proxy.config._
import com.ing.wbaa.gargoyle.proxy.handler.RequestHandlerS3
import com.ing.wbaa.gargoyle.proxy.provider.{ AuthenticationProviderSTS, AuthorizationProviderRanger, LineageProviderAtlas, SignatureProviderAws }

object Server extends App {

  new GargoyleS3Proxy with AuthorizationProviderRanger with RequestHandlerS3 with AuthenticationProviderSTS with LineageProviderAtlas with SignatureProviderAws {
    override implicit lazy val system: ActorSystem = ActorSystem.create("gargoyle-s3proxy")
    override val httpSettings = GargoyleHttpSettings(system)
    override val rangerSettings = GargoyleRangerSettings(system)
    override val storageS3Settings = GargoyleStorageS3Settings(system)
    override val stsSettings: GargoyleStsSettings = GargoyleStsSettings(system)
    override val atlasSettings: GargoyleAtlasSettings = GargoyleAtlasSettings(system)

    // Force Ranger plugin to initialise on startup
    rangerPluginForceInit
  }.startup

}
