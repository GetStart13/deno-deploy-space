import express from "express";
import fetch from "node-fetch";
const app = express();
const port = 3000;

// API endpoint that decodes base64 content from a given URL
app.get("/decode", async (req, res) => {
    const url = req.query.url;

    console.log(url);

    if (!url) {
        return res.status(400).send("URL query parameter is required");
    }

    try {
        // const response = await fetch(url);
        // const base64Content = await response.text();
        // const decodedContent = Buffer.from(base64Content, "base64").toString("utf-8");
        // const content = decodeURI(decodedContent);
        res.send("content");
    } catch (error) {
        console.error("Error fetching or decoding:", error);
        res.status(500).send("Error fetching or decoding");
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
