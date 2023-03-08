from brand import Brand

if __name__ == '__main__':
    github = Brand(name='GitHub', brand='github', tlds=['com', 'co.uk'], sub_domains=['www', '*.services'])
    apple = Brand(name='Apple', brand='apple', tlds=['com', 'dk'], sub_domains=['www', 'icloud'])
    json = Brand.Schema().dumps([github, apple], many=True, indent='\t');

    with open(file='rules.json', mode='w+') as f:
        f.write(json)
