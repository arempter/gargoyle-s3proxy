package nl.wbaa.gargoyle.proxy

object Server {
  def main(args: Array[String]): Unit = {
    val server = new S3Proxy()
    server.start()
  }

}
