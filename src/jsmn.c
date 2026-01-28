/*
 * MIT License
 *
 * Copyright (c) 2010 Serge A. Zaitsev
 */
#include "jsmn.h"

#include <stddef.h>

static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser, jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *tok;

    if (parser->toknext >= num_tokens) {
        return NULL;
    }
    tok = &tokens[parser->toknext++];
    tok->start = tok->end = -1;
    tok->size = 0;
#ifdef JSMN_PARENT_LINKS
    tok->parent = -1;
#endif
    return tok;
}

static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type, int start, int end) {
    token->type = type;
    token->start = start;
    token->end = end;
    token->size = 0;
}

static int jsmn_parse_primitive(jsmn_parser *parser, const char *js, size_t len,
                                jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *token;
    int start;

    start = parser->pos;

    for (; parser->pos < len; parser->pos++) {
        switch (js[parser->pos]) {
            case ':':
            case '\t':
            case '\r':
            case '\n':
            case ' ':
            case ',':
            case ']':
            case '}':
                goto found;
            default:
                /* to quiet a warning from gcc*/
                break;
        }
        if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
            parser->pos = start;
            return JSMN_ERROR_INVAL;
        }
    }
found:
    if (tokens == NULL) {
        parser->pos--;
        return 0;
    }
    token = jsmn_alloc_token(parser, tokens, num_tokens);
    if (token == NULL) {
        parser->pos = start;
        return JSMN_ERROR_NOMEM;
    }
    jsmn_fill_token(token, JSMN_PRIMITIVE, start, parser->pos);
#ifdef JSMN_PARENT_LINKS
    token->parent = parser->toksuper;
#endif
    parser->pos--;
    return 0;
}

static int jsmn_parse_string(jsmn_parser *parser, const char *js, size_t len,
                             jsmntok_t *tokens, size_t num_tokens) {
    jsmntok_t *token;

    int start = parser->pos;

    parser->pos++;

    for (; parser->pos < len; parser->pos++) {
        char c = js[parser->pos];

        if (c == '"') {
            if (tokens == NULL) {
                return 0;
            }
            token = jsmn_alloc_token(parser, tokens, num_tokens);
            if (token == NULL) {
                parser->pos = start;
                return JSMN_ERROR_NOMEM;
            }
            jsmn_fill_token(token, JSMN_STRING, start + 1, parser->pos);
#ifdef JSMN_PARENT_LINKS
            token->parent = parser->toksuper;
#endif
            return 0;
        }

        if (c == '\\' && parser->pos + 1 < len) {
            parser->pos++;
            switch (js[parser->pos]) {
                case '"':
                case '/':
                case '\\':
                case 'b':
                case 'f':
                case 'r':
                case 'n':
                case 't':
                    break;
                case 'u':
                    parser->pos += 4;
                    break;
                default:
                    parser->pos = start;
                    return JSMN_ERROR_INVAL;
            }
        }
    }
    parser->pos = start;
    return JSMN_ERROR_PART;
}

void jsmn_init(jsmn_parser *parser) {
    parser->pos = 0;
    parser->toknext = 0;
    parser->toksuper = -1;
}

int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
               jsmntok_t *tokens, unsigned int num_tokens) {
    int r;
    int i;
    jsmntok_t *token;

    for (; parser->pos < len; parser->pos++) {
        char c = js[parser->pos];
        jsmntype_t type;

        switch (c) {
            case '{':
            case '[':
                if (tokens == NULL) {
                    break;
                }
                token = jsmn_alloc_token(parser, tokens, num_tokens);
                if (token == NULL) {
                    return JSMN_ERROR_NOMEM;
                }
                if (parser->toksuper != -1) {
                    tokens[parser->toksuper].size++;
#ifdef JSMN_PARENT_LINKS
                    token->parent = parser->toksuper;
#endif
                }
                token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
                token->start = parser->pos;
                parser->toksuper = (int)(parser->toknext - 1);
                break;
            case '}':
            case ']':
                if (tokens == NULL) {
                    break;
                }
                type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
#ifdef JSMN_PARENT_LINKS
                if (parser->toknext < 1) {
                    return JSMN_ERROR_INVAL;
                }
                token = &tokens[parser->toknext - 1];
                for (;;) {
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) {
                            return JSMN_ERROR_INVAL;
                        }
                        token->end = parser->pos + 1;
                        parser->toksuper = token->parent;
                        break;
                    }
                    if (token->parent == -1) {
                        if (token->type != type || parser->toksuper == -1) {
                            return JSMN_ERROR_INVAL;
                        }
                        break;
                    }
                    token = &tokens[token->parent];
                }
#else
                for (i = (int)parser->toknext - 1; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) {
                            return JSMN_ERROR_INVAL;
                        }
                        token->end = parser->pos + 1;
                        parser->toksuper = -1;
                        break;
                    }
                }
                if (i == -1) {
                    return JSMN_ERROR_INVAL;
                }
                for (; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        parser->toksuper = i;
                        break;
                    }
                }
#endif
                break;
            case '"':
                r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
                if (r < 0) {
                    return r;
                }
                if (parser->toksuper != -1 && tokens != NULL) {
                    tokens[parser->toksuper].size++;
                }
                break;
            case '\t':
            case '\r':
            case '\n':
            case ' ':
            case ':':
            case ',':
                break;
            default:
                r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
                if (r < 0) {
                    return r;
                }
                if (parser->toksuper != -1 && tokens != NULL) {
                    tokens[parser->toksuper].size++;
                }
                break;
        }
    }

    if (tokens != NULL) {
        for (i = (int)parser->toknext - 1; i >= 0; i--) {
            if (tokens[i].start != -1 && tokens[i].end == -1) {
                return JSMN_ERROR_PART;
            }
        }
    }

    return (int)parser->toknext;
}
