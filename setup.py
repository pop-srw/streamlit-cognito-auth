from setuptools import setup, find_packages

setup(
    name="streamlit-cognito-auth",
    version="0.1.3",
    packages=find_packages("src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=[
        "boto3",
        "python-jose",
        "warrant",
        "streamlit",
        "extra_streamlit_components",
    ],
    author="Sarawin Khemmachotikun",
    author_email="khemmachotikun.s@gmail.com",
    description="A Streamlit component for authenticating users with AWS Cognito",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/pop-srw",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
