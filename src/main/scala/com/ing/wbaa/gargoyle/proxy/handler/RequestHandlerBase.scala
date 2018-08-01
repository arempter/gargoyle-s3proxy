package com.ing.wbaa.gargoyle.proxy.handler

import akka.http.scaladsl.model.{ HttpRequest, HttpResponse, RemoteAddress }

import scala.concurrent.Future

trait RequestHandlerBase {
  def validateUserRequest(request: HttpRequest, secretKey: String): Boolean
  def executeRequest(request: HttpRequest, clientAddress: RemoteAddress): Future[HttpResponse]
}
