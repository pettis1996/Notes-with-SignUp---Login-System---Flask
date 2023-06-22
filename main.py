from website import create_app 

app = create_app()

# This line is for only when we run this app and NOT when importing it
if __name__ == '__main__':
    app.run(debug=True) # Debug=False to disable debug for production