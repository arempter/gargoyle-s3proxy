package nl.wbaa.gargoyle.proxy.providers

import java.io.InputStream
import java.net.URI

import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.RawHeader
import akka.stream.Materializer
import akka.stream.scaladsl.StreamConverters
import com.amazonaws._
import com.amazonaws.auth.{ AWS3Signer, AWS4Signer, BasicAWSCredentials }
import com.amazonaws.http.{ AmazonHttpClient, ExecutionContext, HttpMethodName }
import com.amazonaws.services.s3.internal.S3StringResponseHandler
import com.amazonaws.util.BinaryUtils
import com.typesafe.config.ConfigFactory
import org.apache.http.client.methods._
import org.apache.http.client.utils.URIBuilder
import org.apache.http.entity.BasicHttpEntity
import org.apache.http.impl.client.{ BasicResponseHandler, HttpClients }
import org.apache.http.message.BasicHeader
import org.apache.http.protocol.HttpContext
import org.apache.http.{ Header, HttpRequestInterceptor }

import scala.collection.mutable
import scala.concurrent.Future

/**
 * S3 request generation methods, based on AWS Signer class
 * requires admin user AWS credentials
 *
 */
private class ContentHash extends AWS4Signer {
  def calculate(request: SignableRequest[_]) = super.calculateContentHash(request)

  // hack to test payload hash
  // other option is to copy x-amz-content-sha256 from incomming request
  def calculateContentHash(payloadStream: InputStream): String = {
    val contentSha256 = BinaryUtils.toHex(hash(payloadStream))
    contentSha256
  }
}

object AWSSignatureProvider {
  private val config = ConfigFactory.load().getConfig("s3.server")
  private val accessKey = config.getString("aws_access_key")
  private val secretKey = config.getString("aws_secret_key")
  val s3Host = config.getString("host")
  val s3Port = config.getInt("port")
  val s3Endpoint = s"http://$s3Host:$s3Port"

  val s3credentials = new BasicAWSCredentials(accessKey, secretKey)
  private val cephRGW = new URI(s3Endpoint)

  def s3Request(service: String) = new DefaultRequest(service)

  /**
   * Prepares S3 request based on user request
   *
   * @param method
   * @param path
   * @param request
   * @param endpoint
   * @return
   */
  def generateS3Request(
    method: HttpMethodName,
    path: String,
    params: Option[String],
    content: InputStream,
    request: DefaultRequest[_] = s3Request("s3"),
    endpoint: URI = cephRGW): DefaultRequest[_] = {

    import scala.collection.JavaConverters._

    // convert request rawQueryString to Map
    def convertParams = {
      val rawQueryString = params.getOrElse("")

      if (rawQueryString.length > 1) {
        rawQueryString match {
          // for aws subresource ?acl etc.
          case queryStr if queryStr.length > 1 && !queryStr.contains("=") =>
            Map(queryStr -> List[String]().asJava)
          // single param=value
          case queryStr if queryStr.contains("=") && !queryStr.contains("&") =>
            val params = queryStr.split("=").toList
            Map(params(0) -> List(params(1)).asJava)
          // multiple param=value
          case queryStr if queryStr.contains("&") =>
            queryStr.split("&").toList.map { param =>
              param.split("=").toList
            }.map { paramValuePair =>
              if (paramValuePair.length == 1) {
                (paramValuePair(0), List[String]().asJava) // check it possible in aws
              } else {
                (paramValuePair(0), List(paramValuePair(1)).asJava)
              }
            }.toMap
          case _ => Map[String, java.util.List[String]]().empty
        }
      } else {
        Map[String, java.util.List[String]]().empty
      }
    }

    println("converted params: " + convertParams.values.nonEmpty)

    // add values to Default request for signature
    request.setHttpMethod(method)
    request.setEndpoint(endpoint)
    if (convertParams.asJava.entrySet().size() >= 1) {
      request.setResourcePath(path)
      request.setParameters(convertParams.asJava)
    } else {
      request.setResourcePath(path)
    }

    //request.setContent(content)
    println("generated request:" + request.getParameters)
    request
  }

  /**
   * Signs S3 request with provided credentials. During sign AWS specific headers are added to request
   *
   * @param request
   * @param cred
   * @param signerVer
   * @param region
   */
  private def signS3Request(request: DefaultRequest[_], cred: BasicAWSCredentials, signerVer: String = "v4", region: String = "us-east-1"): Unit = {
    signerVer match {
      case "v3" =>
        val singer = new AWS3Signer()
        singer.sign(request, cred)

      case "v4" =>
        val signer = new AWS4Signer()
        signer.setRegionName(region)
        signer.setServiceName(request.getServiceName)
        signer.sign(request, cred)
    }
  }

  // convert AWS response to Akka http response
  def AWStoAkkaHttpResponse(resp: Response[AmazonWebServiceResponse[String]]): HttpResponse = {
    import scala.collection.JavaConverters._

    def convertHeaders(headers: mutable.Map[String, String]) = {
      headers.keys.map(k =>
        RawHeader(k, headers.get(k).get)
      ).toList
    }

    new HttpResponse(
      resp.getHttpResponse.getStatusCode,
      convertHeaders(resp.getHttpResponse.getHeaders.asScala),
      resp.getAwsResponse.getResult,
      HttpProtocols.`HTTP/1.1`)
  }

  /**
   * Sends request to S3 backend using AmazonHttpClient
   *
   * @param request
   * @return
   */
  def execS3RequestAWSHttpClient(request: DefaultRequest[_], method: String, content: InputStream): Future[HttpResponse] = {
    import scala.concurrent.ExecutionContext.Implicits.global

    try {
      val clientConf = new ClientConfiguration()
      clientConf.addHeader("x-amz-content-sha256", new ContentHash().calculateContentHash(content)) //needs to be based on user

      signS3Request(request, s3credentials)
      println("signed request:" + request.getParameters())

      val response = new AmazonHttpClient(clientConf)
        .requestExecutionBuilder()
        .executionContext(new ExecutionContext(true))
        .request(request)
        //      .execute()
        .execute(new S3StringResponseHandler())

      Future(AWStoAkkaHttpResponse(response))
    } catch {
      case e: Exception => throw new Exception(e)
    }
  }

  /**
   * Translates user request and executes it using Proxy credentials
   *
   * @param request
   * @return
   */
  def translateRequestWithTermination(request: HttpRequest)(implicit mat: Materializer) = {
    import akka.stream.scaladsl.StreamConverters

    val path = request.uri.path.toString()
    val params = request.uri.rawQueryString
    val content = request.entity.withoutSizeLimit().dataBytes.runWith(StreamConverters.asInputStream())

    val method = request.method.value match {
      case "GET"    => HttpMethodName.GET
      case "POST"   => HttpMethodName.POST
      case "PUT"    => HttpMethodName.PUT
      case "DELETE" => HttpMethodName.DELETE
    }

    val proxyRequest = generateS3Request(method, path, params, content)
    execS3RequestAWSHttpClient(proxyRequest, request.method.value, content)
  }

  // test with Apache Http Commons instead of AWSHttp
  def translateRequestWithTerminationApacheHttp(request: HttpRequest)(implicit mat: Materializer): Future[HttpResponse] = {
    import scala.concurrent.ExecutionContext.Implicits.global

    val responseHandler = new BasicResponseHandler()

    def convertHeaders(headers: Array[Header]) = {
      headers.map(h => RawHeader(h.getName, h.getValue)).toList
    }

    val result = execS3RequestApacheHttpClient(request)

    Future(
      new HttpResponse(
        result.getStatusLine.getStatusCode,
        convertHeaders(result.getAllHeaders),
        responseHandler.handleResponse(result),
        HttpProtocols.`HTTP/1.1`)
    )
  }
  // test with Apache Http Commons instead of AWSHttp
  def execS3RequestApacheHttpClient(request: HttpRequest)(implicit mat: Materializer): CloseableHttpResponse = {
    import scala.collection.JavaConverters._

    val method = request.method.value match {
      case "GET"    => HttpMethodName.GET
      case "POST"   => HttpMethodName.POST
      case "PUT"    => HttpMethodName.PUT
      case "DELETE" => HttpMethodName.DELETE
    }
    val path = request.uri.path.toString()
    val params = request.uri.rawQueryString
    val content = request.entity.dataBytes.runWith(StreamConverters.asInputStream())
    val proxyRequest = generateS3Request(method, path, params, content)
    //    val originalSHA256 = request.getHeader("x-amz-content-sha256").get().value()

    // add headers and generate new signature
    proxyRequest.addHeader("Content-Type", request.entity.contentType.toString())
    proxyRequest.addHeader("x-amz-content-sha256", new ContentHash().calculateContentHash(content))
    signS3Request(proxyRequest, s3credentials)
    val signedHeaders: Array[Header] = proxyRequest.getHeaders.asScala.map(h => new BasicHeader(h._1, h._2)).toArray

    // apache http client setup
    val baseUri =
      new URIBuilder()
        .setScheme("http")
        .setHost(s3Host)
        .setPort(s3Port)
        .setPath(path)
    // add query params
    if (params.getOrElse("").length > 1)
      baseUri.setQuery(params.get)

    val httpClient = HttpClients.createDefault()
    val httpEntity = new BasicHttpEntity()
    httpEntity.setContent(content)
    httpEntity.setContentLength(request.entity.contentLengthOption.getOrElse(0))

    val httpRequest = request.method.value match {
      case "GET" =>
        val httpReq = new HttpGet(baseUri.build)
        httpReq
      case "POST" =>
        val httpReq = new HttpPost(baseUri.build)
        httpReq.setEntity(httpEntity)
        httpReq
      case "PUT" =>
        val httpReq = new HttpPut(baseUri.build)
        httpReq.setEntity(httpEntity)
        httpReq
      case "DELETE" => new HttpDelete(baseUri.build())
    }
    // add new headers to request
    httpRequest.setHeaders(signedHeaders)

    println("request to s3: " + httpRequest.getAllHeaders.toList)

    httpClient.execute(httpRequest)
  }

  // test with Apache Http Commons instead of AWSHttp without resignature on proxy
  def proxyUsingApacheHttp(request: HttpRequest)(implicit mat: Materializer): Future[HttpResponse] = {
    import scala.collection.JavaConverters._

    val path = request.uri.path.toString()
    val params = request.uri.rawQueryString
    val content = request.entity.dataBytes.runWith(StreamConverters.asInputStream())

    val httpClient = HttpClients.custom().addInterceptorLast(
      new HttpRequestInterceptor() {
        def process(request: org.apache.http.HttpRequest, context: HttpContext) {
          request.removeHeaders("Timeout-Access")
        }
      }).disableContentCompression().build() // interceptor is not required, just testing removal of different headers

    val baseUri =
      new URIBuilder()
        .setScheme("http")
        .setHost(s3Host)
        .setPort(s3Port)
        .setPath(path)

    if (params.getOrElse("").length > 1)
      baseUri.setQuery(params.get)

    val httpEntity = new BasicHttpEntity()
    httpEntity.setContent(content)
    httpEntity.setContentLength(request.entity.contentLengthOption.getOrElse(0))

    val httpRequest = request.method.value match {
      case "GET" =>
        val httpReq = new HttpGet(baseUri.build)
        httpReq
      case "POST" =>
        val httpReq = new HttpPost(baseUri.build)
        httpReq.setEntity(httpEntity)
        httpReq
      case "PUT" =>
        val httpReq = new HttpPut(baseUri.build)
        httpReq.setEntity(httpEntity)
        httpReq
      case "DELETE" => new HttpDelete(baseUri.build())
    }

    val originalHeaders: Array[Header] = request.getHeaders.asScala.map(h => new BasicHeader(h.name(), h.value())).toArray
    httpRequest.setHeaders(originalHeaders)
    httpRequest.addHeader("Content-Type", request.entity.contentType.toString())

    println("request to s3: " + httpRequest.getAllHeaders.toList)

    val result = httpClient.execute(httpRequest)

    // convert response to akka HttpResponse
    val responseHandler = new BasicResponseHandler()

    def convertHeaders(headers: Array[Header]) = {
      headers.map(h => RawHeader(h.getName, h.getValue)).toList
    }

    import scala.concurrent.ExecutionContext.Implicits.global
    Future(
      new HttpResponse(
        result.getStatusLine.getStatusCode,
        convertHeaders(result.getAllHeaders),
        responseHandler.handleResponse(result),
        HttpProtocols.`HTTP/1.1`)
    )
  }

}
