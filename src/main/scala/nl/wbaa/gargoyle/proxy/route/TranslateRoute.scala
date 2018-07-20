package nl.wbaa.gargoyle.proxy.route

import akka.http.scaladsl.server.Directives._
import akka.http.scaladsl.server.Route
import com.typesafe.scalalogging.LazyLogging
import nl.wbaa.gargoyle.proxy.providers.AWSSignatureProvider.translateRequestWithTermination

trait TranslateRoute extends LazyLogging {

  def proxyWithTermination() =
    Route {
      extractRequestContext { requestCtx =>
        try {
          val res = translateRequestWithTermination(requestCtx.request)
          complete(res)
        } catch {
          case ex: Exception => throw new Exception(ex.getMessage)
        }
      }
    }

}
