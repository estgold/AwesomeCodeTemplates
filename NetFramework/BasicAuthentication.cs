public class BasicAuthenticationAttribute : ActionFilterAttribute
{
    public string BasicRealm { get; set; }
    protected string Username { get; set; }
    protected string Password { get; set; }

    public BasicAuthenticationAttribute(string username, string password)
    {
        this.Username = username;
        this.Password = password;
    }

    public override void OnActionExecuting(ActionExecutingContext filterContext)
    {
        var req = filterContext.HttpContext.Request;
        var auth = req.Headers["Authorization"];
        if (!String.IsNullOrEmpty(auth))
        {
            var cred = System.Text.ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(auth.Substring(6))).Split(':');
            var user = new { Name = cred[0], Pass = cred[1] };
            if (user.Name == Username && user.Pass == Password) return;
        }
        filterContext.HttpContext.Response.AddHeader("WWW-Authenticate", String.Format("Basic realm=\"{0}\"", BasicRealm ?? "Ryadel"));
        /// thanks to eismanpat for this line: http://www.ryadel.com/en/http-basic-authentication-asp-net-mvc-using-custom-actionfilter/#comment-2507605761
        filterContext.Result = new HttpUnauthorizedResult();
    }
}

/* 
source - https://stackoverflow.com/questions/20144364/basic-authentication-in-asp-net-mvc-5
It can be used to put under Basic Authentication a whole controller:

[BasicAuthenticationAttribute("your-username", "your-password", 
BasicRealm = "your-realm")]
public class HomeController : BaseController
{
        ...
}

or a specific ActionResult:

public class HomeController : BaseController
{
    [BasicAuthenticationAttribute("your-username", "your-password", 
        BasicRealm = "your-realm")]
    public ActionResult Index() 
    {
        ...
    }
}


 */