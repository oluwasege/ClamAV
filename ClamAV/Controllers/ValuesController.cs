using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using nClam;

namespace ClamAV.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private readonly ILogger<ValuesController> _logger;
        private readonly IConfiguration _configuration;
        public ValuesController(ILogger<ValuesController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }
        [HttpPost]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return Content("file not selected");

            var ms = new MemoryStream();
            file.OpenReadStream().CopyTo(ms);
            byte[] fileBytes = ms.ToArray();

            try
            {
                _logger.LogInformation("ClamAV scan begin for file {0}", file.FileName);
                var clam = new ClamClient(_configuration.GetSection("ClamAVServer:URL").Value,
                                          Convert.ToInt32(this._configuration["ClamAVServer:Port"]));
                var scanResult = await clam.SendAndScanFileAsync(fileBytes);
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        _logger.LogInformation("The file is clean! ScanResult:{1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.VirusDetected:
                        _logger.LogError("Virus Found! Virus name: {1}", scanResult.InfectedFiles.FirstOrDefault().VirusName);
                        break;
                    case ClamScanResults.Error:
                        _logger.LogError("An error occured while scaning the file! ScanResult: {1}", scanResult.RawResult);
                        break;
                    case ClamScanResults.Unknown:
                        this._logger.LogError("Unknown scan result while scaning the file! ScanResult: {0}", scanResult.RawResult);
                        break;
                }
            }
            catch (Exception ex)
            {

                _logger.LogError("ClamAV Scan Exception: {0}", ex.ToString());
            }
            _logger.LogInformation("ClamAV scan completed for file {0}", file.FileName);

            return Ok("Index");
        }
    }
}
