using Fido2NetLib;
using Fido2NetLib.Objects;
using System.Text;
using idp.Data;
using idp.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace idp.Services;

public class WebAuthnService
{
    private readonly Fido2 _fido2;
    private readonly IMemoryCache _cache;
    private readonly AppDbContext _context;
    private readonly ILogger<WebAuthnService> _logger;

    public WebAuthnService(Fido2 fido2, IMemoryCache cache, AppDbContext context, ILogger<WebAuthnService> logger)
    {
        _fido2 = fido2;
        _cache = cache;
        _context = context;
        _logger = logger;
    }

    // REGISTRATION
    public CredentialCreateOptions StartRegistration(Guid userId, string username)
    {
        _logger.LogDebug("Starting WebAuthn registration for user {UserId}", userId);
        var user = new Fido2User
        {
            DisplayName = username,
            Name = username,
            Id = Encoding.UTF8.GetBytes(userId.ToString())
        };

        var existingCreds = _context.WebAuthnCredentials
            .Where(c => c.UserId.ToString() == userId.ToString())
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialIdBytes))
            .ToList();

        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = user,
            ExcludeCredentials = existingCreds,
            AuthenticatorSelection = new AuthenticatorSelection(),
            AttestationPreference = AttestationConveyancePreference.None
        });
        
        _logger.LogDebug("Generated registration options for user {UserId}", userId);

        _cache.Set($"registration:{userId}", options, TimeSpan.FromMinutes(5));

        return options;
    }

    public async Task<WebAuthnCredential> FinishRegistration(Guid userId, AuthenticatorAttestationRawResponse clientResponse)
    {
        _logger.LogDebug("Finishing WebAuthn registration for user {UserId}", userId);
        var options = _cache.Get<CredentialCreateOptions>($"registration:{userId}");
        if (options == null)
            throw new Exception("Registration options not found");

        var result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = clientResponse,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = async (args, ct) =>
            {
                return !await _context.WebAuthnCredentials
                    .AnyAsync(c => c.CredentialIdBytes.SequenceEqual(args.CredentialId), ct);
            }
        });

        var credential = new WebAuthnCredential
        {
            UserId = userId,
            CredentialIdBytes = result.Id,
            PublicKey = result.PublicKey,
            SignCount = result.SignCount
        };

        _context.WebAuthnCredentials.Add(credential);
        await _context.SaveChangesAsync();

        _logger.LogDebug("WebAuthn registration completed for user {UserId}, credential ID: {CredentialId}", userId, Convert.ToBase64String(result.Id));
        
        _cache.Remove($"registration:{userId}");

        return credential;
    }

    // AUTHENTICATION
    public AssertionOptions StartLogin(Guid userId, List<WebAuthnCredential> creds)
    {
        _logger.LogDebug("Starting WebAuthn login for user {UserId}", userId);
        var allowedCredentials = creds
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialIdBytes))
            .ToList();

        var options = _fido2.GetAssertionOptions(
            allowedCredentials,
            UserVerificationRequirement.Preferred
        );
        
        if (options == null)
            throw new Exception("Login options not found");

        _logger.LogDebug("Generated login options for user {UserId}", userId);
        
        _cache.Set($"login:{userId}", options, TimeSpan.FromMinutes(5));

        return options;
    }

    public async Task<bool> FinishLogin(Guid userId, AuthenticatorAssertionRawResponse clientResponse, WebAuthnCredential storedCredential)
    {
        _logger.LogDebug("Finishing WebAuthn login for user {UserId}", userId);
        var options = _cache.Get<AssertionOptions>($"login:{userId}");
        if (options == null)
            throw new Exception("Login options not found");

        var result = await _fido2.MakeAssertionAsync(
            new MakeAssertionParams
            {
                AssertionResponse = clientResponse,
                OriginalOptions = options,
                StoredPublicKey = storedCredential.PublicKey,
                StoredSignatureCounter = storedCredential.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = async (args, ct) =>
                {
                    var cred = await _context.WebAuthnCredentials
                        .FirstOrDefaultAsync(c => c.CredentialIdBytes.SequenceEqual(args.CredentialId), ct);

                    return cred != null && cred.UserId == userId;
                }
            }
        );

        storedCredential.SignCount = result.SignCount;

        _context.WebAuthnCredentials.Update(storedCredential);
        await _context.SaveChangesAsync();

        _logger.LogDebug("WebAuthn login completed for user {UserId}, credential ID: {CredentialId}", userId, Convert.ToBase64String(storedCredential.CredentialIdBytes));
        
        _cache.Remove($"login:{userId}");

        return true;
    }
}