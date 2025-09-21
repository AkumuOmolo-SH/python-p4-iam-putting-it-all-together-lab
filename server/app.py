#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):

    def post(self):
        data = request.get_json()

        try:
            # Create a new user
            user = User(
                username=data.get("username"),
                image_url=data.get("image_url"),
                bio=data.get("bio")
            )
            # Set password (hashed)
            user.password_hash = data.get("password")

            # Save to database
            db.session.add(user)
            db.session.commit()

            # Store user ID in session
            session["user_id"] = user.id

            # Return user info
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 201

        except Exception as e:
            db.session.rollback()

            # Format error(s) for frontend
            errors = []
            if hasattr(e, "orig"):  # e.g., IntegrityError
                errors.append(str(e.orig))
            else:
                errors.append(str(e))

            return {"errors": errors}, 422
        
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        user = None
        if user_id:
            user = db.session.get(User, user_id)

        if not user:
            # Always return same 401 JSON to satisfy tests
            return {"error": "Not authorized"}, 401
        
        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 200

        




class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        # Look up the user by username
        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            # Password is correct → save user_id in session
            session["user_id"] = user.id

            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200
        else:
            # Wrong username or password
            return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")

        if user_id:
            session.pop("user_id")
            return "", 204
        else:
            return {"error": "Not authorized"}, 401

    

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Not authorized"}, 401

        recipes = Recipe.query.all()
        recipes_list = []
        for recipe in recipes:
            recipes_list.append({
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id if recipe.user else None,
                    "username": recipe.user.username if recipe.user else None,
                    "image_url": recipe.user.image_url if recipe.user else None,
                    "bio": recipe.user.bio if recipe.user else None
                }
            })
        return recipes_list, 200

    def post(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Not authorized"}, 401

        data = request.get_json()
        user = db.session.get(User, user_id)  # Modern SQLAlchemy 2.x style

        if not user:
            return {"error": "User not found"}, 401

        try:
            # Create a new recipe for the logged-in user
            recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user=user
            )

            db.session.add(recipe)
            db.session.commit()

            return {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }
            }, 201

        except (IntegrityError, ValueError) as e:
            db.session.rollback()

            errors = []
            if hasattr(e, "orig"):
                errors.append(str(e.orig))
            else:
                errors.append(str(e))

            return {"errors": errors}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)