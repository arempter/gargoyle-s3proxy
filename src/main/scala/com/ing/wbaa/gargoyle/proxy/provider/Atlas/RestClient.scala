package com.ing.wbaa.gargoyle.proxy.provider.Atlas

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.{ Authorization, BasicHttpCredentials }
import akka.http.scaladsl.unmarshalling.Unmarshal
import akka.stream.ActorMaterializer
import akka.util.ByteString
import com.ing.wbaa.gargoyle.proxy.config.GargoyleAtlasSettings
import com.ing.wbaa.gargoyle.proxy.provider.Atlas.Model.{ createResponse, updateResponse }
import spray.json.{ JsValue, _ }

import scala.concurrent.Future

class RestClient()(implicit system: ActorSystem, atlasSettings: GargoyleAtlasSettings) extends AtlasModelJsonSupport {

  // todo: do I need those here?
  implicit val mat = ActorMaterializer()
  implicit val executionContext = system.dispatcher

  private val http = Http(system)
  private val atlasApiUriV1 = atlasSettings.atlasBaseUri + "/api/atlas"
  private val atlasApiUriV2 = atlasSettings.atlasBaseUri + "/api/atlas/v2"
  private val bulkEntity = "/entity/bulk"
  private val username = atlasSettings.atlasApiUser
  private val password = atlasSettings.atlasApiPassword

  private val authHeader = Authorization(BasicHttpCredentials(username, password))

  // remove?
  def getTypeGUID(typeName: String, value: String): Future[String] = {
    http.singleRequest(HttpRequest(
      HttpMethods.GET,
      atlasApiUriV1 + s"/entities?type=${typeName}&property=qualifiedName&value=${value}"
    ).withHeaders(authHeader))
      .flatMap { case HttpResponse(_, _, entity, _) => entity.dataBytes.runFold(ByteString(""))(_ ++ _).map(b => b.utf8String) }
  }

  def postData(json: JsValue): Future[String] = {
    http.singleRequest(HttpRequest(
      HttpMethods.POST,
      atlasApiUriV2 + bulkEntity,
      Nil,
      HttpEntity(ContentTypes.`application/json`, json.toString)
    ).withHeaders(authHeader))
      .flatMap { response =>
        Unmarshal(response.entity).to[String].map { jsonString =>
          if (jsonString.contains("CREATE")) {
            jsonString.parseJson.convertTo[createResponse].guidAssignments.convertTo[Map[String, String]].values.toList.head
          } else {
            jsonString.parseJson.convertTo[updateResponse].guidAssignments.convertTo[Map[String, String]].values.toList.head
          }
        }
      }
  }
}
