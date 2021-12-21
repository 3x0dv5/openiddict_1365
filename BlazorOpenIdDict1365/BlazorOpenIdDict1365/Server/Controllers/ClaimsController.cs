using System.Security.Claims;
using BlazorOpenIdDict1365.Server.Data;
using BlazorOpenIdDict1365.Server.Models;
using Duende.IdentityServer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace BlazorOpenIdDict1365.Server.Controllers;

// [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
// using the above Authorize will break the server side CLAIMS.
[ApiController, Route("/api/[controller]")]
public class ClaimsController : Controller
{
    private readonly ApplicationDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public ClaimsController(ApplicationDbContext dbContext, 
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost("add-sample")]
    [Authorize]
    public async Task<IActionResult> AddSampleClaims()
    {
        var userId = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (await _dbContext.UserClaims.Where(m => m.UserId == userId).AnyAsync())
            return BadRequest("Already added");

        await _dbContext.AddAsync(new IdentityUserClaim<string>
        {
            ClaimType = "ENTITY_TYPE_1",
            ClaimValue = "VIEW",
            UserId = userId
        });
        await _dbContext.AddAsync(new IdentityUserClaim<string>
        {
            ClaimType = "ENTITY_TYPE_1",
            ClaimValue = "ADD",
            UserId = userId
        });
        await _dbContext.AddAsync(new IdentityUserClaim<string>
        {
            ClaimType = "ENTITY_TYPE_2",
            ClaimValue = "VIEW",
            UserId = userId
        });
        await _dbContext.SaveChangesAsync();
        return Ok();
    }


    [HttpGet("has-claim")]
    [Authorize]
    [ResponseCache(NoStore = true)]
    public async Task<IActionResult> HasClaim([FromQuery]string type, [FromQuery]string value)
    {
        var claims = HttpContext.User.Claims.ToList();
        var userId = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var user = await _userManager.FindByIdAsync(userId);

        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        // await HttpContext.SignInAsync(principal);
        
        var hasClaim = HttpContext.User.HasClaim(type, value);
        return Ok(hasClaim);
    }
}