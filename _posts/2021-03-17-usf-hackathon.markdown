---
layout: post
title: Developing for the USF Hackathon 2021
date: 2021-03-13 12:00:00 -0400
categories: usf hackathon 
---

Led the backend development for the app, [Follow Fido](https://devpost.com/software/follow-fido). (See the Github project [here](https://github.com/andrewscfl/follow-fido).) We had 24 hours to plan, develop, test, and deploy this app. We met this deadline with most components (except the database "delete schedule event") working.

We all agreed on a Python-based backend: Flask as the webserver, and firebase to store all data. The frontend can easily interact with the database by simply navigating to the preset route, and sending the request data, which could be easily parsed into a dict for further editing. I planned this into a structure of three parts:

- `storage.py`: Methods to interact with the storage framework (firebase) library

- `api.py`: A helper to interact with the storage module

- `main.py`: Runs the actual flask routes, using the api module

Using the api level, we were able to streamline our specification, and develop most of the backend, from scratch, within the 24-hour timeframe. (Note: During the actual event, these three layers were combined into one document, `main.py`. This was a mutual agreement for the actual event to mitigate a variety of concerns.)

In future releases, *Follow Fido* may use a more sophisticated web framework. (Flask itself recommends not being used in formal production environments.) In addition, we may consider migrating from firebase once we graduate and lose our free USF licenses. A good alternative would be MongoDB.