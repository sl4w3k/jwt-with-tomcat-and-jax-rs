package pl.ailux.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import pl.ailux.model.Item;
import pl.ailux.model.User;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.LinkedList;
import java.util.List;

import static javax.ws.rs.core.Response.Status.*;

@Slf4j
@Path("/security")
public class JwtSecurityExample {
    private static final String ISSUER = "pl.ailux";
    private static List<JsonWebKey> JWK_LIST;

    static {
        log.info("Inside static initializer...");
        JWK_LIST = new LinkedList<>();
        for (int kid = 1; kid <= 3; kid++) {
            JsonWebKey jwk = null;
            try {
                jwk = RsaJwkGenerator.generateJwk(2048);
                log.info("PUBLIC KEY (" + kid + "): "
                        + jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
            } catch (final JoseException e) {
                log.error("", e);
            }
            jwk.setKeyId(String.valueOf(kid));
            JWK_LIST.add(jwk);
        }
    }

    @Path("/status")
    @GET
    @Produces(MediaType.TEXT_HTML)
    public String returnVersion() {
        return "JwtSecurityExample Status is OK...";
    }

    @Path("/authenticate")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticateCredentials(@HeaderParam("username") final String username,
                                            @HeaderParam("password") final String password){
        log.info("Authenticating User Credentials...");
        final boolean validUserData = isValidUserData(username, password);
        if(!validUserData) {
            return Response.status(PRECONDITION_FAILED)
                    .entity("Please provide proper username and/or password").build();
        }
        final User user = findUserInDatabase(username, password);
        if (user == null) {
            return Response.status(FORBIDDEN)
                    .entity("Access Denied for this functionality !!!").build();
        }
        final String jwt = generateUniqueToken(user);
        return Response.status(200).entity(jwt).build();
    }

    @Path("/finditembyid")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response findItemById(@HeaderParam("token") final String token,
                                 @QueryParam("itemid") final String item_id) {
        log.info("Inside findOrderById...");
        if (token == null) {
            return Response.status(FORBIDDEN)
                    .entity("Access Denied for this functionality !!!").build();
        }
        //FIXME - DRY: use validation in some filter or something else
        if (!isTokenValid(token)) {
            return Response.status(FORBIDDEN)
                    .entity("Access Denied for this functionality !!!").build();
        }
        //FIXME call service instead this
        final Item item = new Item();
        item.setId("1");
        item.setItemId("1234=fsfaew32-1432");
        item.setItemName("something");
        item.setItemQuantity(777);
        item.setItemPrice(123.43);
        return Response.status(OK).entity(item).build();
    }

    private User findUserInDatabase(final String username, final String password) {
       //TODO call some service here
        return new User(username, password);
    }

    private boolean isValidUserData(final String username, final String password) {
        return !StringUtils.isEmpty(username) && !StringUtils.isEmpty(password);
    }

    private String generateUniqueToken(final User user) {
        final RsaJsonWebKey senderJwk = (RsaJsonWebKey) JWK_LIST.get(0);
        senderJwk.setKeyId("1");
        log.info("JWK (1) ===> " + senderJwk.toJson());
        // Create the Claims, which will be the content of the JWT
        final JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(2);
        claims.setSubject(user.getUsername());
        claims.setStringListClaim("roles", user.getRolesList());
        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKeyIdHeaderValue(senderJwk.getKeyId());
        jws.setKey(senderJwk.getPrivateKey());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String jwt = null;
        try {
            jwt = jws.getCompactSerialization();
        } catch (final JoseException e) {
            log.error("", e);
        }
        return jwt;
    }

    private boolean isTokenValid(final String token) {
        final JsonWebKeySet jwks = new JsonWebKeySet(JWK_LIST);
        final JsonWebKey jwk = jwks.findJsonWebKey("1", null,  null,  null);
        log.info("JWK (1) ===> " + jwk.toJson());
        // Validate Token's authenticity and check claims
        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer(ISSUER)
                .setVerificationKey(jwk.getKey())
                .build();
        try {
            //  Validate the JWT and process it to the Claims
            final JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            log.info("JWT validation succeeded! " + jwtClaims);
        } catch (final InvalidJwtException e) {
            log.error("JWT is Invalid: " + e);
            return false;
        }
        return true;
    }
}
