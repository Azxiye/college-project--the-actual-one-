# Week 3 Lab ================================================
# Task 1 ----------------------------------------------------
# name = "Alex"
# age = 20
# height = 1.75
# likes_coding = True
# print("Name:", name, type(name))
# print("Age:", age, type(age))
# print("Height:", height, type(height))
# print("Likes coding:", likes_coding, type(likes_coding))
 
# age_in_days = age * 365
# print("Approximate age in days:", age_in_days)

# introduction = "Hello, my name is " + name + " and I am " + str(age) + " Years old ."
# print(introduction)

# Task 1 Output 
# Name: Alex <class 'str'>
# Age: 20 <class 'int'>
# Height: 1.75 <class 'float'>
# Likes coding: True <class 'bool'>
# Approximate age in days: 7300
# Hello, my name is Alex and I am 20 Years old .

# Task 2 -----------------------------------------------------
# message = "Python programming is fun"
# print("First 6 characters:", message[:6])
# print("Last 3 characters:", message[-3:])
# print("Reversed", message[::-1])

# Task 2 Output
# First 6 characters: Python
# Last 3 characters: fun
# Reversed nuf si gnimmargorp nohtyP

# Task 3 -----------------------------------------------------
# movies = ["Inception", "The Matrix", "Interstellar", "The Dark Knight"]
# print("Original list:", movies)
# print("First movie:", movies[0])
# print("Last movie:", movies[-1])

# movies.append("The Lord of the Rings")
# print("After appending a movie:", movies)

# movies.insert(1, "The Godfather") # dictionaries counts from 0, then 1, 2, 3, etc
# print("After inserting a movie at index 1:", movies)

# Task 3 Output
# Original list: ['Inception', 'The Matrix', 'Interstellar', 'The Dark Knight']
# First movie: Inception
# Last movie: The Dark Knight
# After appending a movie: ['Inception', 'The Matrix', 'Interstellar', 'The Dark Knight', 'The Lord of the Rings']
# After inserting a movie at index 1: ['Inception', 'The Godfather', 'The Matrix', 'Interstellar', 'The Dark Knight', 'The Lord of the Rings']

# Task 4 -----------------------------------------------------
# student = {
#     "name": "Alex",
#     "student_id": "123456",
#     "Courses": ["Python", "Data Science", "Cybersecurity"],
#     "year": 2,
#     "grades" : [78, 45, 67, 69, 61]
# }

# print("Full student record:", student)
# print("name:", student["name"])
# print("year:", student["year"])
# print("grades:", student["grades"])

# Task 4 Output
# Full student record: {'name': 'Alex', 'student_id': '123456', 'Courses': ['Python', 'Data Science', 'Cybersecurity'], 'year': 2, 'grades': [78, 45, 67, 69, 61]}name: Alex
# year: 2
# grades: [78, 45, 67, 69, 61]

# Task 5 -----------------------------------------------------
# def write_shopping_list():
#     groceries = ["milk" , "eggs", "bread", "butter", "cheese"]
#     with open("shopping_list.txt", "w", encoding="utf-8") as file:
#         for item in groceries:
#             file.write(item + "\n")

# def read_shopping_list():
#     with open("shopping_list.txt", "r", encoding="utf-8") as file:
#         items = file.readlines()
#         for number, item in enumerate(items, start=1):
#             print(str(number) + "." + item.strip())

# write_shopping_list()
# read_shopping_list()

# Task 5 Output 
# 1.milk
# 2.eggs
# 3.bread
# 4.butter
# 5.cheese

