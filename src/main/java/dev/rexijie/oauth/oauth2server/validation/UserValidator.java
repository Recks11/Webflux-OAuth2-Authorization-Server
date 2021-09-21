package dev.rexijie.oauth.oauth2server.validation;

import org.bson.Document;
import org.springframework.data.mongodb.core.schema.JsonSchemaObject;
import org.springframework.data.mongodb.core.schema.JsonSchemaProperty;
import org.springframework.data.mongodb.core.schema.MongoJsonSchema;
import org.springframework.data.mongodb.core.validation.Validator;

public class UserValidator implements Validator {
    @Override
    public Document toDocument() {
        var schema = MongoJsonSchema.builder()
                .properties(
                        JsonSchemaProperty.string("username").description("username"),
                        JsonSchemaProperty.string("password").description("user password"))
                .property(JsonSchemaProperty.array("authorities").items(
                        JsonSchemaObject.string().maxLength(0)
                ))
                .required("username", "password")
                .build();
        return schema.toDocument();
    }
}
