from fastapi import FastAPI, Request, Response

from index import handler


app = FastAPI(
    title="Enterprise AI Gateway",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.post("/v1/chat/completions")
async def proxy(request: Request) -> Response:
    body = await request.body()

    event = {
        "body": body.decode("utf-8", errors="strict"),
        "headers": dict(request.headers),
    }

    result = handler(event, None)
    response_headers = result.get("headers", {})
    content_type = response_headers.get(
        "Content-Type",
        "application/json",
    )

    return Response(
        content=result["body"],
        status_code=result["statusCode"],
        media_type=content_type,
    )
